require 'json'
require 'fileutils'
require 'socket'
require 'time'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

def json_safe(value)
  case value
  when Hash
    value.each_with_object({}) { |(key, item), out| out[key] = json_safe(item) }
  when Array
    value.map { |item| json_safe(item) }
  when Float
    value.finite? ? value : nil
  else
    value
  end
end

REPORT_ROOT = ENV.fetch('SC_REPORT_DIR', "/tmp/sc_vendor_results/#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}")
TRIGGER_MODE = ENV.fetch('SC_TRIGGER_MODE', 'dynamic').downcase == 'static' ? 0 : 1
COORDINATION_MODE = Integer(ENV.fetch('SC_COORDINATION_MODE', '0'))
PAYLOAD_NAMES = {
  'SC-PAYLOAD-EXFIL' => 0,
  'SC-PAYLOAD-SP001' => 1,
  'SC-PAYLOAD-SP003' => 2,
  'SC-PAYLOAD-SP006' => 3,
  'SC-PAYLOAD-SP007' => 4,
  'SC-PAYLOAD-SP008' => 5
}.freeze
PAYLOAD_NAME = ENV.fetch('SC_PAYLOAD_ID', 'SC-PAYLOAD-EXFIL').upcase
raise "Unsupported SC_PAYLOAD_ID=#{PAYLOAD_NAME}" unless PAYLOAD_NAMES.key?(PAYLOAD_NAME)
PAYLOAD = PAYLOAD_NAMES.fetch(PAYLOAD_NAME)
STATIC_DELAY_MS = Integer(ENV.fetch('SC_STATIC_DELAY_MS', '5000'))
TRIGGER_ALTITUDE_M = Float(ENV.fetch('SC_TRIGGER_ALTITUDE_M', '350000'))
DESTINATION_IP = ENV.fetch('SC_DESTINATION_IP', 'active-gs')
CI_HOST = ENV.fetch('SC_CI_HOST', 'sc01-nos-fsw')
CI_PORT = Integer(ENV.fetch('SC_CI_PORT', '5012'))
TO_LAB_CMD_MID = 0x18E8
TO_LAB_ENABLE_OUTPUT_CC = 2
NOVATEL_OEM615_CMD_MID = 0x1870
NOVATEL_OEM615_LOG_CC = 4

def read_tlm(target, packet, item)
  tlm("#{target} #{packet} #{item}")
end

def finite_number?(value)
  Float(value).finite?
rescue ArgumentError, TypeError
  false
end

def command(name)
  cmd(name)
  # cFS command delivery and TO_LAB telemetry forwarding are asynchronous.
  # Give the target pipe and ground link a scheduling opportunity before the
  # next evidence snapshot.
  sleep(0.2)
end

# TO_LAB state is intentionally not assumed to survive a normal FSW restart.
# Re-establish the real downlink before asking for benchmark evidence, using
# the same validated cFS command format as the SP008 verifier.
def cfe_checksum(packet)
  value = 0xFF
  packet.each_byte { |byte| value ^= byte }
  value & 0xFF
end

def command_packet(mid, fc, payload = ''.b)
  packet = [mid & 0xFFFF, 0xC000, (8 + payload.bytesize - 7) & 0xFFFF].pack('n n n')
  packet << [fc & 0xFF, 0].pack('C C')
  packet << payload
  packet.setbyte(7, cfe_checksum(packet))
  packet
end

def enable_to_lab_downlink
  ip = DESTINATION_IP.bytes.pack('C*')
  raise "TO_LAB destination is longer than 16 bytes: #{DESTINATION_IP}" if ip.bytesize > 16

  payload = ip + ("\0".b * (16 - ip.bytesize))
  UDPSocket.open { |socket| socket.send(command_packet(TO_LAB_CMD_MID, TO_LAB_ENABLE_OUTPUT_CC, payload), 0, CI_HOST, CI_PORT) }
  sleep(0.3)
end

def request_novatel_gpgga_once
  # FC 4 is the genuine NOVATEL LOG command.  LogType 1 selects GPGGA,
  # whose native cFS parser supplies the latitude/altitude fields used by the
  # dynamic trigger.  PeriodOption 0 selects one bounded GPSFILE sample.
  payload = [1, 0].pack('C C')
  UDPSocket.open { |socket| socket.send(command_packet(NOVATEL_OEM615_CMD_MID, NOVATEL_OEM615_LOG_CC, payload), 0, CI_HOST, CI_PORT) }
end

def nav_profile_command(trigger_altitude_m = TRIGGER_ALTITUDE_M)
  "CFS SC_VENDOR_NAV_SET_PROFILE with TRIGGER_MODE #{TRIGGER_MODE}, COORDINATION_MODE #{COORDINATION_MODE}, PAYLOAD #{PAYLOAD}, RESERVED 0, STATIC_DELAY_MS #{STATIC_DELAY_MS}, TRIGGER_ALTITUDE_M #{trigger_altitude_m}, DESTINATION_IP '#{DESTINATION_IP}'"
end

def snapshot_nav_raw
  {
    sequence: read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'CCSDS_SEQUENCE'),
    armed: read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'ARMED'),
    triggered: read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'TRIGGERED'),
    novatel_packets: read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'NOVATELPACKETCOUNT'),
    coordination_count: read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'COORDINATIONCOUNT'),
    exfil_commands: read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'EXFILCOMMANDCOUNT'),
    payload_invokes: read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'PAYLOADINVOKECOUNT'),
    last_payload_status: read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'LASTPAYLOADSTATUS'),
    last_payload_profile: read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'LASTPAYLOADPROFILE'),
    payload_recovery_count: read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'PAYLOADRECOVERYCOUNT'),
    last_latitude: read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'LASTLATITUDE'),
    last_altitude: read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'LASTALTITUDE')
  }
end

def snapshot_nav
  previous = read_tlm('CFS', 'SC_VENDOR_NAV_HK_TLM', 'CCSDS_SEQUENCE').to_i rescue nil
  command('CFS SC_VENDOR_NAV_REQ_HK')
  current = snapshot_nav_raw
  deadline = Time.now + 4.0
  while !previous.nil? && current[:sequence].to_i == previous && Time.now < deadline
    sleep(0.25)
    current = snapshot_nav_raw
  end
  current.merge(fresh: previous.nil? || current[:sequence].to_i != previous)
end

def snapshot_diag_raw
  {
    sequence: read_tlm('CFS', 'SC_VENDOR_DIAG_HK_TLM', 'CCSDS_SEQUENCE'),
    triggered: read_tlm('CFS', 'SC_VENDOR_DIAG_HK_TLM', 'TRIGGERED'),
    coordination_count: read_tlm('CFS', 'SC_VENDOR_DIAG_HK_TLM', 'COORDINATIONCOUNT'),
    exfil_commands: read_tlm('CFS', 'SC_VENDOR_DIAG_HK_TLM', 'EXFILCOMMANDCOUNT')
  }
end

def snapshot_diag
  previous = read_tlm('CFS', 'SC_VENDOR_DIAG_HK_TLM', 'CCSDS_SEQUENCE').to_i rescue nil
  command('CFS SC_VENDOR_DIAG_REQ_HK')
  current = snapshot_diag_raw
  deadline = Time.now + 4.0
  while !previous.nil? && current[:sequence].to_i == previous && Time.now < deadline
    sleep(0.25)
    current = snapshot_diag_raw
  end
  current.merge(fresh: previous.nil? || current[:sequence].to_i != previous)
end

def wait_for_nav_reset
  deadline = Time.now + 6.0
  current = snapshot_nav
  until current[:armed].to_i == 0 && current[:triggered].to_i == 0 &&
        current[:coordination_count].to_i == 0 && current[:exfil_commands].to_i == 0 || Time.now >= deadline
    sleep(0.25)
    current = snapshot_nav
  end
  current
end

def wait_for_diag_reset
  deadline = Time.now + 6.0
  current = snapshot_diag
  until current[:triggered].to_i == 0 && current[:coordination_count].to_i == 0 &&
        current[:exfil_commands].to_i == 0 || Time.now >= deadline
    sleep(0.25)
    current = snapshot_diag
  end
  current
end

FileUtils.mkdir_p(REPORT_ROOT)
result = {
  scenario_id: 'SC-APP',
  trigger_mode: TRIGGER_MODE,
  coordination_mode: COORDINATION_MODE,
  payload: PAYLOAD_NAME,
  artifact_accepted: true,
  benign_contract_passed: false,
  dormancy_observed: false,
  trigger_observed: false,
  coordination_observed: false,
  payload_invoked: false,
  mission_effect_observed: false,
  payload_recovery_observed: false,
  recovery_observed: false,
  trigger_input_observed: nil,
  trigger_input_valid: nil
}

begin
  enable_to_lab_downlink
  if TRIGGER_MODE == 1
    # The NOS3 NOVATEL component is disabled after a normal FSW reboot.
    # Establish its real device-command path before requesting the telemetry
    # that drives the dynamic vendor trigger.
    command('NOVATEL_OEM615 NOVATEL_OEM615_ENABLE_CC')
    command('NOVATEL_OEM615 NOVATEL_OEM615_REQ_HK')
    sleep(0.5)
  end
  command('CFS SC_VENDOR_NAV_RESET')
  command('CFS SC_VENDOR_DIAG_RESET')
  before_nav = wait_for_nav_reset
  before_diag = wait_for_diag_reset

  dormant_trigger_altitude_m = TRIGGER_MODE == 1 ? 10_000_000 : TRIGGER_ALTITUDE_M
  command(nav_profile_command(dormant_trigger_altitude_m))
  command('CFS SC_VENDOR_NAV_ARM')
  armed_nav = snapshot_nav
  result[:benign_contract_passed] = armed_nav[:armed].to_i == 1
  result[:dormancy_observed] = armed_nav[:triggered].to_i == 0

  command(nav_profile_command) if TRIGGER_MODE == 1

  8.times do
    if TRIGGER_MODE == 1
      request_novatel_gpgga_once
      sleep(0.2)
      command('NOVATEL_OEM615 NOVATEL_OEM615_REQ_DATA')
    end
    sleep(0.5)
  end

  after_nav = snapshot_nav
  after_diag = snapshot_diag
  result[:trigger_observed] = after_nav[:triggered].to_i == 1
  result[:coordination_observed] = COORDINATION_MODE == 0 || after_diag[:triggered].to_i == 1
  result[:payload_invoked] = after_nav[:payload_invokes].to_i > before_nav[:payload_invokes].to_i ||
                             after_nav[:exfil_commands].to_i > before_nav[:exfil_commands].to_i ||
                             after_diag[:exfil_commands].to_i > before_diag[:exfil_commands].to_i
  result[:mission_effect_observed] = result[:payload_invoked] && after_nav[:last_payload_status].to_i == 0
  result[:payload_recovery_observed] = after_nav[:payload_recovery_count].to_i > before_nav[:payload_recovery_count].to_i
  if TRIGGER_MODE == 1
    result[:trigger_input_observed] = after_nav[:novatel_packets].to_i > armed_nav[:novatel_packets].to_i
    result[:trigger_input_valid] = finite_number?(after_nav[:last_altitude])
    if result[:trigger_input_observed] && !result[:trigger_input_valid]
      result[:classification] = 'INCONCLUSIVE_ENV_INVALID_NOVATEL_INPUT'
    end
  end

  command('CFS SC_VENDOR_NAV_STOP')
  stopped_nav = snapshot_nav
  result[:recovery_observed] = stopped_nav[:armed].to_i == 0
  result[:passed] = result[:mission_effect_observed] && result[:payload_recovery_observed] && result[:recovery_observed]
  result[:evidence] = { before_nav: before_nav, armed_nav: armed_nav, after_nav: after_nav,
                        before_diag: before_diag, after_diag: after_diag, stopped_nav: stopped_nav,
                        dormant_trigger_altitude_m: dormant_trigger_altitude_m,
                        activation_trigger_altitude_m: TRIGGER_ALTITUDE_M }
rescue Exception => error
  result[:error] = { class: error.class.to_s, message: error.message,
                     backtrace: error.backtrace ? error.backtrace.first(8) : [] }
  result[:passed] = false
ensure
  safe_result = json_safe(result)
  File.write(File.join(REPORT_ROOT, 'score.json'), JSON.pretty_generate(safe_result) + "\n")
  puts JSON.pretty_generate(safe_result)
end
