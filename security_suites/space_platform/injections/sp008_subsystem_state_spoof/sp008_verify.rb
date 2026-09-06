require 'json'
require 'fileutils'
require 'socket'
require 'time'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

SCENARIO_ID = 'SP008'
SCENARIO_NAME = 'Satellite subsystem state spoofing'
REPORT_ROOT = ENV.fetch('SP008_REPORT_DIR', "/tmp/sp008_subsystem_state_spoof_results/#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}")
CI_HOST = ENV.fetch('SP008_CI_HOST', 'sc01-nos-fsw')
CI_PORT = ENV.fetch('SP008_CI_PORT', '5012').to_i
SELECTED_PROFILE_IDS = ENV.fetch('SP008_ONLY', '').split(',').map(&:strip).reject(&:empty?)

SP008_CMD_MID = 0x19FA
SP008_REQ_HK_MID = 0x19FB
SP008_HK_MID = 0x09FA
SP008_START_EPS_HEALTHY_SPOOF_CC = 2
SP008_STOP_SPOOF_CC = 3
SP008_START_PROFILE_CC = 4

SP008_PROFILE_EPS_HEALTHY_WHILE_REAL_LOW_POWER = 1
SP008_PROFILE_ADCS_INERTIAL_STABLE_WHILE_REAL_PASSIVE = 2
SP008_PROFILE_RW_ENABLED_NOMINAL_WHILE_REAL_DISABLED = 3
SP008_PROFILE_THRUSTER_ENABLED_WHILE_REAL_DISABLED = 4
SP008_PROFILE_TORQUER_ACTIVE_WHILE_REAL_DISABLED = 5
SP008_PROFILE_MGR_SCIENCE_WHILE_REAL_SAFE = 6
SP008_PROFILE_GPS_POSITION_SPOOF_WHILE_REAL_ORBIT_NOMINAL = 7

GENERIC_EPS_REQ_HK_MID = 0x191B
GENERIC_EPS_HK_TLM_MID = 0x091A
GENERIC_ADCS_CMD_MID = 0x1940
GENERIC_ADCS_GNC_MID = 0x0943
GENERIC_RW_CMD_MID = 0x1992
GENERIC_RW_SEND_HK_MID = 0x1993
GENERIC_RW_HK_TLM_MID = 0x0993
GENERIC_THRUSTER_CMD_MID = 0x18EA
GENERIC_THRUSTER_REQ_HK_MID = 0x18EB
GENERIC_THRUSTER_HK_TLM_MID = 0x08EA
GENERIC_TORQUER_CMD_MID = 0x193A
GENERIC_TORQUER_REQ_HK_MID = 0x193B
GENERIC_TORQUER_HK_TLM_MID = 0x093A
MGR_CMD_MID = 0x18F8
MGR_REQ_HK_MID = 0x18F9
MGR_HK_TLM_MID = 0x08F8
NOVATEL_OEM615_CMD_MID = 0x1870
NOVATEL_OEM615_REQ_TLM_MID = 0x1871
NOVATEL_OEM615_DEVICE_TLM_MID = 0x0871
TO_LAB_CMD_MID = 0x18E8
TO_LAB_ENABLE_OUTPUT_CC = 2
EVS_EVENT_MID = 0x0808

GENERIC_ADCS_SET_MODE_CC = 2
GENERIC_ADCS_SEND_GNC_CC = 5
GENERIC_ADCS_MODE_PASSIVE = 0
GENERIC_ADCS_MODE_INERTIAL = 3
GENERIC_RW_REQ_DATA_CC = 2
GENERIC_RW_DISABLE_CC = 5
GENERIC_THRUSTER_DISABLE_CC = 3
GENERIC_TORQUER_DISABLE_CC = 3
MGR_SET_MODE_CC = 2
MGR_MODE_SAFE = 1
MGR_MODE_SCIENCE = 3
NOVATEL_OEM615_REQ_DATA_TLM_CC = 1

LOW_BATT_THRESHOLD = ENV.fetch('SP008_LOW_BATT_THRESHOLD', '24.0').to_f
HEALTHY_BATT_THRESHOLD = ENV.fetch('SP008_HEALTHY_BATT_THRESHOLD', '27.0').to_f
HEALTHY_SA_THRESHOLD = ENV.fetch('SP008_HEALTHY_SA_THRESHOLD', '30.0').to_f
ADCS_ZERO_RATE_THRESHOLD = ENV.fetch('SP008_ADCS_ZERO_RATE_THRESHOLD', '0.0001').to_f
RW_NOMINAL_MOMENTUM_THRESHOLD = ENV.fetch('SP008_RW_NOMINAL_MOMENTUM_THRESHOLD', '0.01').to_f
GPS_SPOOF_LAT = ENV.fetch('SP008_GPS_SPOOF_LAT', '51.5074').to_f
GPS_SPOOF_LON = ENV.fetch('SP008_GPS_SPOOF_LON', '-0.1278').to_f
GPS_SPOOF_ALT = ENV.fetch('SP008_GPS_SPOOF_ALT', '500000.0').to_f
GPS_POSITION_TOLERANCE_DEG = ENV.fetch('SP008_GPS_POSITION_TOLERANCE_DEG', '0.001').to_f
GPS_ALT_TOLERANCE_M = ENV.fetch('SP008_GPS_ALT_TOLERANCE_M', '50.0').to_f
BASELINE_TIMEOUT_SECONDS = ENV.fetch('SP008_BASELINE_TIMEOUT', '30').to_f
SPOOF_TIMEOUT_SECONDS = ENV.fetch('SP008_SPOOF_TIMEOUT', '8').to_f
RESTORE_TIMEOUT_SECONDS = ENV.fetch('SP008_RESTORE_TIMEOUT', '12').to_f

ATTACK_DESCRIPTION = {
  attack_entry: 'Benchmark-controlled malicious cFS app publishes real subsystem telemetry MIDs',
  affected_channels: [
    'GENERIC_EPS GENERIC_EPS_HK_TLM, MID 0x091A',
    'GENERIC_ADCS GENERIC_ADCS_GNC, MID 0x0943',
    'GENERIC_REACTION_WHEEL GENRW_HK_TLM_T, MID 0x0993',
    'GENERIC_THRUSTER GENERIC_THRUSTER_HK_TLM, MID 0x08EA',
    'GENERIC_TORQUER GENERIC_TORQUER_HK_TLM_T, MID 0x093A',
    'MGR MGR_HK_TLM, MID 0x08F8',
    'NOVATEL_OEM615 NOVATEL_OEM615_DATA_TLM, MID 0x0871'
  ],
  cps_type: 'Subsystem state authenticity failure',
  security_consequence: 'The ground/cFS world model for subsystem health, mode, attitude, or dynamics can be overwritten while the real subsystem remains in a different state.',
  pass_rule: 'real_state_before && ground_latest_state_spoofed_during_attack && real_state_after_spoof_stopped'
}.freeze

PROFILES = [
  {
    id: SP008_PROFILE_EPS_HEALTHY_WHILE_REAL_LOW_POWER,
    name: 'EPS_HEALTHY_WHILE_REAL_LOW_POWER',
    target_packet: 'GENERIC_EPS GENERIC_EPS_HK_TLM',
    target_mid: GENERIC_EPS_HK_TLM_MID,
    run: :run_eps_profile
  },
  {
    id: SP008_PROFILE_ADCS_INERTIAL_STABLE_WHILE_REAL_PASSIVE,
    name: 'ADCS_INERTIAL_STABLE_WHILE_REAL_PASSIVE',
    target_packet: 'GENERIC_ADCS GENERIC_ADCS_GNC',
    target_mid: GENERIC_ADCS_GNC_MID,
    run: :run_adcs_profile
  },
  {
    id: SP008_PROFILE_RW_ENABLED_NOMINAL_WHILE_REAL_DISABLED,
    name: 'RW_ENABLED_NOMINAL_WHILE_REAL_DISABLED',
    target_packet: 'GENERIC_REACTION_WHEEL GENRW_HK_TLM_T',
    target_mid: GENERIC_RW_HK_TLM_MID,
    run: :run_rw_profile
  },
  {
    id: SP008_PROFILE_THRUSTER_ENABLED_WHILE_REAL_DISABLED,
    name: 'THRUSTER_ENABLED_WHILE_REAL_DISABLED',
    target_packet: 'GENERIC_THRUSTER GENERIC_THRUSTER_HK_TLM',
    target_mid: GENERIC_THRUSTER_HK_TLM_MID,
    run: :run_thruster_profile
  },
  {
    id: SP008_PROFILE_TORQUER_ACTIVE_WHILE_REAL_DISABLED,
    name: 'TORQUER_ACTIVE_WHILE_REAL_DISABLED',
    target_packet: 'GENERIC_TORQUER GENERIC_TORQUER_HK_TLM_T',
    target_mid: GENERIC_TORQUER_HK_TLM_MID,
    run: :run_torquer_profile
  },
  {
    id: SP008_PROFILE_MGR_SCIENCE_WHILE_REAL_SAFE,
    name: 'MGR_SCIENCE_WHILE_REAL_SAFE',
    target_packet: 'MGR MGR_HK_TLM',
    target_mid: MGR_HK_TLM_MID,
    run: :run_mgr_profile
  },
  {
    id: SP008_PROFILE_GPS_POSITION_SPOOF_WHILE_REAL_ORBIT_NOMINAL,
    name: 'GPS_POSITION_SPOOF_WHILE_REAL_ORBIT_NOMINAL',
    target_packet: 'NOVATEL_OEM615 NOVATEL_OEM615_DATA_TLM',
    target_mid: NOVATEL_OEM615_DEVICE_TLM_MID,
    run: :run_gps_profile
  }
].freeze

class SkipProfile < StandardError
  attr_reader :classification

  def initialize(classification, message)
    @classification = classification
    super(message)
  end
end

def json_safe(value)
  case value
  when Hash
    value.each_with_object({}) { |(key, item), out| out[key] = json_safe(item) }
  when Array
    value.map { |item| json_safe(item) }
  when Numeric, String, TrueClass, FalseClass, NilClass
    value
  else
    value.to_s
  end
end

def write_json(path, object)
  FileUtils.mkdir_p(File.dirname(path))
  File.write(path, JSON.pretty_generate(json_safe(object)) + "\n")
end

def numeric(value)
  return value.to_f if value.is_a?(Numeric)

  value.to_s.strip.to_f
end

def clean_string(value)
  value.to_s.delete("\u0000").strip
end

def tlm_num(target, packet, item)
  numeric(tlm("#{target} #{packet} #{item}"))
end

def tlm_i(target, packet, item)
  tlm_num(target, packet, item).to_i
end

def tlm_label_optional(target, packet, item)
  clean_string(tlm("#{target} #{packet} #{item}"))
rescue Exception
  nil
end

def tlm_raw_i_optional(target, packet, item)
  numeric(tlm_raw("#{target} #{packet} #{item}")).to_i
rescue Exception
  nil
end

def telemetry_packet_exists?(target, packet)
  Cosmos::System.telemetry.packet(target, packet)
  true
rescue Exception
  false
end

def command_available?(target, command)
  Cosmos::System.commands.packet(target, command)
  true
rescue Exception
  false
end

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

def send_udp(packet)
  UDPSocket.open do |socket|
    socket.send(packet, 0, CI_HOST, CI_PORT)
  end
  { ok: true, host: CI_HOST, port: CI_PORT, bytes: packet.bytesize, checksum_result: cfe_checksum(packet) }
rescue Exception => error
  { ok: false, host: CI_HOST, port: CI_PORT, error_class: error.class.to_s, error: error.message }
end

def raw_to_lab_add(stream_mid, buffer_limit = 64)
  payload = [stream_mid & 0xFFFFFFFF].pack('V') + [0, 0, buffer_limit & 0xFF, 0].pack('C C C C')
  send_udp(command_packet(TO_LAB_CMD_MID, 6, payload))
end

def raw_to_lab_enable
  ip = 'active-gs'.bytes.pack('C*')
  payload = ip + ("\0".b * (16 - ip.bytesize))
  send_udp(command_packet(TO_LAB_CMD_MID, TO_LAB_ENABLE_OUTPUT_CC, payload))
end

def ensure_routes
  routes = { to_lab_enable: raw_to_lab_enable }
  sleep(0.2)
  {
    generic_eps_hk: GENERIC_EPS_HK_TLM_MID,
    generic_adcs_gnc: GENERIC_ADCS_GNC_MID,
    generic_rw_hk: GENERIC_RW_HK_TLM_MID,
    generic_thruster_hk: GENERIC_THRUSTER_HK_TLM_MID,
    generic_torquer_hk: GENERIC_TORQUER_HK_TLM_MID,
    mgr_hk: MGR_HK_TLM_MID,
    novatel_oem615_data: NOVATEL_OEM615_DEVICE_TLM_MID,
    sp008_hk: SP008_HK_MID,
    evs_event: EVS_EVENT_MID
  }.each do |name, mid|
    routes[name] = raw_to_lab_add(mid, 64)
    sleep(0.15)
  end
  routes
end

def wait_until(timeout = 6.0, interval = 0.3)
  deadline = Time.now + timeout
  last = nil
  until Time.now >= deadline
    last = yield
    return last.merge(matched: true) if last[:matched]
    sleep(interval)
  end
  last ? last.merge(matched: false) : { matched: false }
end

def safe_cmd(command_text)
  cmd(command_text)
  { ok: true, command: command_text }
rescue Exception => error
  { ok: false, command: command_text, error_class: error.class.to_s, error: error.message }
end

def set_eps_low_power
  commands = []
  if command_available?('SIM_CMDBUS_BRIDGE', 'GENERIC_EPS_SIM_STATE_OF_CHARGE')
    commands << safe_cmd('SIM_CMDBUS_BRIDGE GENERIC_EPS_SIM_STATE_OF_CHARGE with STATE_OF_CHARGE 5')
  else
    commands << { ok: false, command: 'SIM_CMDBUS_BRIDGE GENERIC_EPS_SIM_STATE_OF_CHARGE', reason: 'command_not_loaded' }
  end

  %w[
    GENERIC_EPS_SIM_TOGGLE_POSX_PANEL
    GENERIC_EPS_SIM_TOGGLE_NEGX_PANEL
    GENERIC_EPS_SIM_TOGGLE_POSY_PANEL
    GENERIC_EPS_SIM_TOGGLE_NEGY_PANEL
    GENERIC_EPS_SIM_TOGGLE_NEGZ_PANEL
  ].each do |cmd_name|
    next unless command_available?('SIM_CMDBUS_BRIDGE', cmd_name)

    param_name = cmd_name.sub('GENERIC_EPS_SIM_', '')
    commands << safe_cmd("SIM_CMDBUS_BRIDGE #{cmd_name} with #{param_name} 0")
    sleep(0.15)
  end

  if command_available?('SIM_CMDBUS_BRIDGE', 'GENERIC_EPS_SIM_RATE_OF_CHARGE')
    commands << safe_cmd('SIM_CMDBUS_BRIDGE GENERIC_EPS_SIM_RATE_OF_CHARGE with RATE_OF_CHARGE -200')
  end

  { commands: commands, ok: commands.any? { |entry| entry[:ok] } }
end

def set_adcs_passive
  {
    set_mode: send_udp(command_packet(GENERIC_ADCS_CMD_MID, GENERIC_ADCS_SET_MODE_CC, [GENERIC_ADCS_MODE_PASSIVE].pack('C'))),
    request_gnc: request_adcs_gnc
  }
end

def set_rw_disabled
  commands = []
  3.times do |wheel|
    commands << send_udp(command_packet(GENERIC_RW_CMD_MID, GENERIC_RW_DISABLE_CC, [wheel, 0].pack('C s<'))).merge(wheel: wheel)
    sleep(0.15)
  end
  { commands: commands, request_hk: request_rw_hk, ok: commands.all? { |entry| entry[:ok] } }
end

def set_thruster_disabled
  {
    disable: send_udp(command_packet(GENERIC_THRUSTER_CMD_MID, GENERIC_THRUSTER_DISABLE_CC, ''.b)),
    request_hk: request_thruster_hk
  }
end

def set_torquer_disabled
  {
    disable: send_udp(command_packet(GENERIC_TORQUER_CMD_MID, GENERIC_TORQUER_DISABLE_CC, ''.b)),
    request_hk: request_torquer_hk
  }
end

def set_mgr_safe
  {
    set_mode: send_udp(command_packet(MGR_CMD_MID, MGR_SET_MODE_CC, [MGR_MODE_SAFE].pack('C'))),
    request_hk: request_mgr_hk
  }
end

def capture_gps_orbit_baseline
  { request_data: request_gps_data }
end

def request_eps_hk
  send_udp(command_packet(GENERIC_EPS_REQ_HK_MID, 0, ''.b))
end

def request_adcs_gnc
  send_udp(command_packet(GENERIC_ADCS_CMD_MID, GENERIC_ADCS_SEND_GNC_CC, ''.b))
end

def request_rw_hk
  send_udp(command_packet(GENERIC_RW_SEND_HK_MID, 0, ''.b))
end

def request_thruster_hk
  send_udp(command_packet(GENERIC_THRUSTER_REQ_HK_MID, 0, ''.b))
end

def request_torquer_hk
  send_udp(command_packet(GENERIC_TORQUER_REQ_HK_MID, 0, ''.b))
end

def request_mgr_hk
  send_udp(command_packet(MGR_REQ_HK_MID, 0, ''.b))
end

def request_gps_data
  send_udp(command_packet(NOVATEL_OEM615_REQ_TLM_MID, NOVATEL_OEM615_REQ_DATA_TLM_CC, ''.b))
end

def request_sp008_hk
  send_udp(command_packet(SP008_REQ_HK_MID, 0, ''.b))
end

def sp008_start_profile(profile_id)
  payload = [profile_id.to_i, 0].pack('v v')
  send_udp(command_packet(SP008_CMD_MID, SP008_START_PROFILE_CC, payload)).merge(profile_id: profile_id)
end

def sp008_start_eps_legacy
  send_udp(command_packet(SP008_CMD_MID, SP008_START_EPS_HEALTHY_SPOOF_CC, ''.b))
end

def sp008_stop_spoof
  send_udp(command_packet(SP008_CMD_MID, SP008_STOP_SPOOF_CC, ''.b))
end

def read_eps_hk(refresh: true)
  return { available: false, reason: 'GENERIC_EPS telemetry dictionary is not loaded' } unless telemetry_packet_exists?('GENERIC_EPS', 'GENERIC_EPS_HK_TLM')

  if refresh
    request_eps_hk
    sleep(0.35)
  end

  switch_label = tlm_label_optional('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'SWITCH_0_STATE')
  {
    available: true,
    sequence: tlm_i('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'CCSDS_SEQUENCE'),
    batt_voltage: tlm_num('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'BATT_VOLTAGE'),
    sa_voltage: tlm_num('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'SA_VOLTAGE'),
    bus_3p3v: tlm_num('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'BUS_3P3V'),
    bus_5p0v: tlm_num('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'BUS_5P0V'),
    bus_12v: tlm_num('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'BUS_12V'),
    sw_0_current: tlm_num('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'SW_0_CURRENT'),
    switch_0_state: switch_label,
    switch_0_state_raw: tlm_raw_i_optional('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'SWITCH_0_STATE'),
    raw_battery_voltage: tlm_i('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'RAW_BATTERY_VOLTAGE'),
    raw_sa_voltage: tlm_i('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'RAW_SA_VOLTAGE'),
    observed_at: Time.now.utc.iso8601
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def read_adcs_gnc(refresh: true)
  return { available: false, reason: 'GENERIC_ADCS GNC telemetry dictionary is not loaded' } unless telemetry_packet_exists?('GENERIC_ADCS', 'GENERIC_ADCS_GNC')

  if refresh
    request_adcs_gnc
    sleep(0.35)
  end

  mode_label = tlm_label_optional('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'MODE')
  q_valid_label = tlm_label_optional('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'Q_VALID')
  {
    available: true,
    sequence: tlm_i('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'CCSDS_SEQUENCE'),
    mode: mode_label,
    mode_raw: tlm_raw_i_optional('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'MODE'),
    q_valid: q_valid_label,
    q_valid_raw: tlm_raw_i_optional('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'Q_VALID'),
    qbn_0: tlm_num('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'QBN_0'),
    qbn_1: tlm_num('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'QBN_1'),
    qbn_2: tlm_num('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'QBN_2'),
    qbn_3: tlm_num('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'QBN_3'),
    wbn_x: tlm_num('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'WBN_X'),
    wbn_y: tlm_num('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'WBN_Y'),
    wbn_z: tlm_num('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'WBN_Z'),
    sun_valid_raw: tlm_raw_i_optional('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'SUN_VALID'),
    observed_at: Time.now.utc.iso8601
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def read_rw_hk(refresh: true)
  if refresh
    request_rw_hk
    sleep(0.35)
  end

  primary = read_rw_hk_packet('GENERIC_REACTION_WHEEL', 'GENRW_HK_TLM_T',
                              enabled_items: %w[DEVICE_ENABLED_RW0 DEVICE_ENABLED_RW1 DEVICE_ENABLED_RW2],
                              momentum_items: %w[MOMENTUM_NMS_0 MOMENTUM_NMS_1 MOMENTUM_NMS_2])
  return primary if packet_fresh?(primary)

  alias_sample = read_rw_hk_packet('CFS', 'SP006_RW_HK_TLM',
                                   enabled_items: %w[DEVICEENABLED_RW0 DEVICEENABLED_RW1 DEVICEENABLED_RW2],
                                   momentum_items: %w[MOMENTUM_RW0 MOMENTUM_RW1 MOMENTUM_RW2])
  return alias_sample if packet_fresh?(alias_sample)

  primary[:available] ? primary : alias_sample
end

def read_rw_hk_packet(target, packet, enabled_items:, momentum_items:)
  return { available: false, reason: "#{target} #{packet} telemetry dictionary is not loaded" } unless telemetry_packet_exists?(target, packet)

  {
    available: true,
    source_target: target,
    source_packet: packet,
    sequence: tlm_i(target, packet, 'CCSDS_SEQUENCE'),
    enabled_rw0_raw: tlm_raw_i_optional(target, packet, enabled_items[0]),
    enabled_rw1_raw: tlm_raw_i_optional(target, packet, enabled_items[1]),
    enabled_rw2_raw: tlm_raw_i_optional(target, packet, enabled_items[2]),
    enabled_rw0: tlm_label_optional(target, packet, enabled_items[0]),
    enabled_rw1: tlm_label_optional(target, packet, enabled_items[1]),
    enabled_rw2: tlm_label_optional(target, packet, enabled_items[2]),
    momentum_0: tlm_num(target, packet, momentum_items[0]),
    momentum_1: tlm_num(target, packet, momentum_items[1]),
    momentum_2: tlm_num(target, packet, momentum_items[2]),
    observed_at: Time.now.utc.iso8601
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def read_thruster_hk(refresh: true)
  if refresh
    request_thruster_hk
    sleep(0.35)
  end

  primary = read_thruster_hk_packet('GENERIC_THRUSTER', 'GENERIC_THRUSTER_HK_TLM',
                                    enabled_item: 'DEVICE_ENABLED',
                                    cmd_err_item: 'CMD_ERR_COUNT',
                                    device_err_item: 'DEVICE_ERR_COUNT')
  return primary if packet_fresh?(primary)

  alias_sample = read_thruster_hk_packet('CFS', 'SP006_THRUSTER_HK_TLM',
                                         enabled_item: 'DEVICEENABLED',
                                         cmd_err_item: 'COMMANDERRCOUNT',
                                         device_err_item: 'DEVICEERRORCOUNT')
  return alias_sample if packet_fresh?(alias_sample)

  primary[:available] ? primary : alias_sample
end

def read_thruster_hk_packet(target, packet, enabled_item:, cmd_err_item:, device_err_item:)
  return { available: false, reason: "#{target} #{packet} telemetry dictionary is not loaded" } unless telemetry_packet_exists?(target, packet)

  {
    available: true,
    source_target: target,
    source_packet: packet,
    sequence: tlm_i(target, packet, 'CCSDS_SEQUENCE'),
    device_enabled: tlm_label_optional(target, packet, enabled_item),
    device_enabled_raw: tlm_raw_i_optional(target, packet, enabled_item),
    cmd_err_count: tlm_i(target, packet, cmd_err_item),
    device_err_count: tlm_i(target, packet, device_err_item),
    observed_at: Time.now.utc.iso8601
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def read_torquer_hk(refresh: true)
  packet = 'GENERIC_TORQUER_HK_TLM_T'
  return { available: false, reason: 'GENERIC_TORQUER telemetry dictionary is not loaded' } unless telemetry_packet_exists?('GENERIC_TORQUER', packet)

  if refresh
    request_torquer_hk
    sleep(0.35)
  end

  {
    available: true,
    sequence: tlm_i('GENERIC_TORQUER', packet, 'CCSDS_SEQUENCE'),
    device_enabled: tlm_label_optional('GENERIC_TORQUER', packet, 'DEVICE_ENABLED'),
    device_enabled_raw: tlm_raw_i_optional('GENERIC_TORQUER', packet, 'DEVICE_ENABLED'),
    torquer_period: tlm_i('GENERIC_TORQUER', packet, 'TORQUER_PERIOD'),
    direction_0: tlm_i('GENERIC_TORQUER', packet, 'TORQUER_DIRECTION_0'),
    percent_on_0: tlm_i('GENERIC_TORQUER', packet, 'TORQUER_PERCENT_ON_0'),
    direction_1: tlm_i('GENERIC_TORQUER', packet, 'TORQUER_DIRECTION_1'),
    percent_on_1: tlm_i('GENERIC_TORQUER', packet, 'TORQUER_PERCENT_ON_1'),
    direction_2: tlm_i('GENERIC_TORQUER', packet, 'TORQUER_DIRECTION_2'),
    percent_on_2: tlm_i('GENERIC_TORQUER', packet, 'TORQUER_PERCENT_ON_2'),
    observed_at: Time.now.utc.iso8601
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def read_mgr_hk(refresh: true)
  packet = 'MGR_HK_TLM'
  return { available: false, reason: 'MGR telemetry dictionary is not loaded' } unless telemetry_packet_exists?('MGR', packet)

  if refresh
    request_mgr_hk
    sleep(0.35)
  end

  {
    available: true,
    sequence: tlm_i('MGR', packet, 'CCSDS_SEQUENCE'),
    spacecraft_mode: tlm_label_optional('MGR', packet, 'SPACECRAFT_MODE'),
    spacecraft_mode_raw: tlm_raw_i_optional('MGR', packet, 'SPACECRAFT_MODE'),
    science_status: tlm_label_optional('MGR', packet, 'SCIENCE_STATUS'),
    science_status_raw: tlm_raw_i_optional('MGR', packet, 'SCIENCE_STATUS'),
    science_pass_count: tlm_i('MGR', packet, 'SCIENCE_PASS_COUNT'),
    ak_config_raw: tlm_raw_i_optional('MGR', packet, 'AK_CONFIG'),
    conus_config_raw: tlm_raw_i_optional('MGR', packet, 'CONUS_CONFIG'),
    hi_config_raw: tlm_raw_i_optional('MGR', packet, 'HI_CONFIG'),
    observed_at: Time.now.utc.iso8601
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def read_gps_data(refresh: true)
  packet = 'NOVATEL_OEM615_DATA_TLM'
  return { available: false, reason: 'NOVATEL_OEM615 data telemetry dictionary is not loaded' } unless telemetry_packet_exists?('NOVATEL_OEM615', packet)

  if refresh
    request_gps_data
    sleep(0.35)
  end

  {
    available: true,
    sequence: tlm_i('NOVATEL_OEM615', packet, 'CCSDS_SEQUENCE'),
    gps_weeks: tlm_i('NOVATEL_OEM615', packet, 'GPS_WEEKS'),
    gps_seconds: tlm_i('NOVATEL_OEM615', packet, 'GPS_SECONDS'),
    ecef_x: tlm_num('NOVATEL_OEM615', packet, 'ECEF_X'),
    ecef_y: tlm_num('NOVATEL_OEM615', packet, 'ECEF_Y'),
    ecef_z: tlm_num('NOVATEL_OEM615', packet, 'ECEF_Z'),
    vel_x: tlm_num('NOVATEL_OEM615', packet, 'VEL_X'),
    vel_y: tlm_num('NOVATEL_OEM615', packet, 'VEL_Y'),
    vel_z: tlm_num('NOVATEL_OEM615', packet, 'VEL_Z'),
    lat: tlm_num('NOVATEL_OEM615', packet, 'LAT'),
    lon: tlm_num('NOVATEL_OEM615', packet, 'LON'),
    alt: tlm_num('NOVATEL_OEM615', packet, 'ALT'),
    observed_at: Time.now.utc.iso8601
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def read_sp008_hk(refresh: true)
  return { available: false, reason: 'SP008 telemetry dictionary is not loaded' } unless telemetry_packet_exists?('CFS', 'SP008_HK_TLM')

  if refresh
    request_sp008_hk
    sleep(0.25)
  end

  {
    available: true,
    sequence: tlm_i('CFS', 'SP008_HK_TLM', 'CCSDS_SEQUENCE'),
    cmd_count: tlm_i('CFS', 'SP008_HK_TLM', 'COMMANDCOUNT'),
    err_count: tlm_i('CFS', 'SP008_HK_TLM', 'COMMANDERRORCOUNT'),
    spoof_active: tlm_i('CFS', 'SP008_HK_TLM', 'SPOOFACTIVE'),
    active_profile_id: tlm_i('CFS', 'SP008_HK_TLM', 'ACTIVEPROFILEID'),
    last_profile_id: tlm_i('CFS', 'SP008_HK_TLM', 'LASTPROFILEID'),
    last_spoofed_mid: tlm_i('CFS', 'SP008_HK_TLM', 'LASTSPOOFEDMID'),
    spoof_start_count: tlm_i('CFS', 'SP008_HK_TLM', 'SPOOFSTARTCOUNT'),
    spoof_stop_count: tlm_i('CFS', 'SP008_HK_TLM', 'SPOOFSTOPCOUNT'),
    forged_packet_count: tlm_i('CFS', 'SP008_HK_TLM', 'FORGEDPACKETCOUNT'),
    transmit_error_count: tlm_i('CFS', 'SP008_HK_TLM', 'TRANSMITERRORCOUNT'),
    forged_eps_hk_count: tlm_i('CFS', 'SP008_HK_TLM', 'FORGEDEPSHKCOUNT'),
    forged_adcs_gnc_count: tlm_i('CFS', 'SP008_HK_TLM', 'FORGEDADCSGNCCOUNT'),
    forged_rw_hk_count: tlm_i('CFS', 'SP008_HK_TLM', 'FORGEDRWHKCOUNT'),
    forged_thruster_hk_count: tlm_i('CFS', 'SP008_HK_TLM', 'FORGEDTHRUSTERHKCOUNT'),
    forged_torquer_hk_count: tlm_i('CFS', 'SP008_HK_TLM', 'FORGEDTORQUERHKCOUNT'),
    forged_mgr_hk_count: tlm_i('CFS', 'SP008_HK_TLM', 'FORGEDMGRHKCOUNT'),
    forged_gps_data_count: tlm_i('CFS', 'SP008_HK_TLM', 'FORGEDGPSDATACOUNT'),
    last_transmit_status: tlm_i('CFS', 'SP008_HK_TLM', 'LASTTRANSMITSTATUS'),
    last_raw_battery_voltage: tlm_i('CFS', 'SP008_HK_TLM', 'LASTRAWBATTERYVOLTAGE'),
    last_raw_solar_array_voltage: tlm_i('CFS', 'SP008_HK_TLM', 'LASTRAWSOLARARRAYVOLTAGE'),
    last_adcs_mode: tlm_i('CFS', 'SP008_HK_TLM', 'LASTADCSMODE'),
    last_adcs_q_valid: tlm_i('CFS', 'SP008_HK_TLM', 'LASTADCSQVALID')
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def eps_low?(sample)
  sample[:available] && sample[:batt_voltage].to_f < LOW_BATT_THRESHOLD
end

def eps_healthy?(sample)
  sample[:available] &&
    sample[:batt_voltage].to_f >= HEALTHY_BATT_THRESHOLD &&
    sample[:sa_voltage].to_f >= HEALTHY_SA_THRESHOLD &&
    sample[:bus_3p3v].to_f >= 3.0 &&
    sample[:bus_5p0v].to_f >= 4.5 &&
    sample[:bus_12v].to_f >= 11.0
end

def adcs_passive?(sample)
  return false unless sample[:available]

  sample[:mode_raw].to_i == GENERIC_ADCS_MODE_PASSIVE || sample[:mode].to_s.upcase.include?('PASSIVE')
end

def near_zero?(value)
  value.to_f.abs <= ADCS_ZERO_RATE_THRESHOLD
end

def adcs_inertial_stable?(sample)
  return false unless sample[:available]

  inertial = sample[:mode_raw].to_i == GENERIC_ADCS_MODE_INERTIAL || sample[:mode].to_s.upcase.include?('INERTIAL')
  q_valid = sample[:q_valid_raw].to_i == 1 || sample[:q_valid].to_s.upcase == 'VALID'
  stable_q = sample[:qbn_0].to_f.abs <= 0.001 &&
             sample[:qbn_1].to_f.abs <= 0.001 &&
             sample[:qbn_2].to_f.abs <= 0.001 &&
             (sample[:qbn_3].to_f - 1.0).abs <= 0.001
  stable_rate = near_zero?(sample[:wbn_x]) && near_zero?(sample[:wbn_y]) && near_zero?(sample[:wbn_z])

  inertial && q_valid && stable_q && stable_rate
end

def packet_fresh?(sample)
  sample[:available] && sample[:sequence].to_i != 0
end

def enabled_value?(raw, label)
  (!raw.nil? && raw.to_i == 1) || label.to_s.upcase.include?('ENABLED')
end

def disabled_value?(raw, label)
  (!raw.nil? && raw.to_i == 0) || label.to_s.upcase.include?('DISABLED')
end

def rw_disabled?(sample)
  packet_fresh?(sample) &&
    disabled_value?(sample[:enabled_rw0_raw], sample[:enabled_rw0]) &&
    disabled_value?(sample[:enabled_rw1_raw], sample[:enabled_rw1]) &&
    disabled_value?(sample[:enabled_rw2_raw], sample[:enabled_rw2])
end

def rw_enabled_nominal?(sample)
  packet_fresh?(sample) &&
    enabled_value?(sample[:enabled_rw0_raw], sample[:enabled_rw0]) &&
    enabled_value?(sample[:enabled_rw1_raw], sample[:enabled_rw1]) &&
    enabled_value?(sample[:enabled_rw2_raw], sample[:enabled_rw2]) &&
    sample[:momentum_0].to_f.abs <= RW_NOMINAL_MOMENTUM_THRESHOLD &&
    sample[:momentum_1].to_f.abs <= RW_NOMINAL_MOMENTUM_THRESHOLD &&
    sample[:momentum_2].to_f.abs <= RW_NOMINAL_MOMENTUM_THRESHOLD
end

def thruster_disabled?(sample)
  packet_fresh?(sample) && disabled_value?(sample[:device_enabled_raw], sample[:device_enabled])
end

def thruster_enabled?(sample)
  packet_fresh?(sample) && enabled_value?(sample[:device_enabled_raw], sample[:device_enabled]) &&
    sample[:device_err_count].to_i.zero?
end

def torquer_disabled?(sample)
  sample[:available] && disabled_value?(sample[:device_enabled_raw], sample[:device_enabled])
end

def torquer_active?(sample)
  sample[:available] && enabled_value?(sample[:device_enabled_raw], sample[:device_enabled]) &&
    sample[:torquer_period].to_i.positive? &&
    [sample[:percent_on_0], sample[:percent_on_1], sample[:percent_on_2]].all? { |value| value.to_i.positive? }
end

def mgr_safe?(sample)
  sample[:available] &&
    (sample[:spacecraft_mode_raw].to_i == MGR_MODE_SAFE || sample[:spacecraft_mode].to_s.upcase == 'SAFE')
end

def mgr_science?(sample)
  sample[:available] &&
    (sample[:spacecraft_mode_raw].to_i == MGR_MODE_SCIENCE || sample[:spacecraft_mode].to_s.upcase == 'SCIENCE') &&
    sample[:science_pass_count].to_i.positive? &&
    sample[:ak_config_raw].to_i == 1 &&
    sample[:conus_config_raw].to_i == 1 &&
    sample[:hi_config_raw].to_i == 1
end

def gps_orbit_nominal?(sample)
  sample[:available] &&
    sample[:lat].to_f.between?(-90.0, 90.0) &&
    sample[:lon].to_f.between?(-180.0, 180.0) &&
    sample[:alt].to_f > 100_000.0 &&
    !gps_spoof_position?(sample)
end

def gps_spoof_position?(sample)
  sample[:available] &&
    (sample[:lat].to_f - GPS_SPOOF_LAT).abs <= GPS_POSITION_TOLERANCE_DEG &&
    (sample[:lon].to_f - GPS_SPOOF_LON).abs <= GPS_POSITION_TOLERANCE_DEG &&
    (sample[:alt].to_f - GPS_SPOOF_ALT).abs <= GPS_ALT_TOLERANCE_M
end

def wait_for_eps_low_baseline(timeout)
  wait_until(timeout, 0.8) do
    sample = read_eps_hk(refresh: true)
    { matched: eps_low?(sample), sample: sample, low_threshold: LOW_BATT_THRESHOLD }
  end
end

def wait_for_eps_healthy_spoof(timeout)
  wait_until(timeout, 0.25) do
    sample = read_eps_hk(refresh: false)
    { matched: eps_healthy?(sample), sample: sample, healthy_batt_threshold: HEALTHY_BATT_THRESHOLD,
      healthy_sa_threshold: HEALTHY_SA_THRESHOLD }
  end
end

def wait_for_adcs_passive_baseline(timeout)
  wait_until(timeout, 0.8) do
    sample = read_adcs_gnc(refresh: true)
    { matched: adcs_passive?(sample), sample: sample, expected_mode: 'PASSIVE' }
  end
end

def wait_for_adcs_inertial_stable_spoof(timeout)
  wait_until(timeout, 0.25) do
    sample = read_adcs_gnc(refresh: false)
    { matched: adcs_inertial_stable?(sample), sample: sample, expected_mode: 'INERTIAL',
      zero_rate_threshold: ADCS_ZERO_RATE_THRESHOLD }
  end
end

def wait_for_rw_disabled_baseline(timeout)
  wait_until(timeout, 0.8) do
    sample = read_rw_hk(refresh: true)
    { matched: rw_disabled?(sample), sample: sample, expected_enabled_flags: [0, 0, 0] }
  end
end

def wait_for_rw_enabled_nominal_spoof(timeout)
  wait_until(timeout, 0.25) do
    sample = read_rw_hk(refresh: false)
    { matched: rw_enabled_nominal?(sample), sample: sample, expected_enabled_flags: [1, 1, 1],
      nominal_momentum_threshold: RW_NOMINAL_MOMENTUM_THRESHOLD }
  end
end

def wait_for_thruster_disabled_baseline(timeout)
  wait_until(timeout, 0.8) do
    sample = read_thruster_hk(refresh: true)
    { matched: thruster_disabled?(sample), sample: sample, expected_device_enabled: 0 }
  end
end

def wait_for_thruster_enabled_spoof(timeout)
  wait_until(timeout, 0.25) do
    sample = read_thruster_hk(refresh: false)
    { matched: thruster_enabled?(sample), sample: sample, expected_device_enabled: 1 }
  end
end

def wait_for_torquer_disabled_baseline(timeout)
  wait_until(timeout, 0.8) do
    sample = read_torquer_hk(refresh: true)
    { matched: torquer_disabled?(sample), sample: sample, expected_device_enabled: 0 }
  end
end

def wait_for_torquer_active_spoof(timeout)
  wait_until(timeout, 0.25) do
    sample = read_torquer_hk(refresh: false)
    { matched: torquer_active?(sample), sample: sample, expected_device_enabled: 1, expected_percent_on_min: 1 }
  end
end

def wait_for_mgr_safe_baseline(timeout)
  wait_until(timeout, 0.8) do
    sample = read_mgr_hk(refresh: true)
    { matched: mgr_safe?(sample), sample: sample, expected_mode: 'SAFE' }
  end
end

def wait_for_mgr_science_spoof(timeout)
  wait_until(timeout, 0.25) do
    sample = read_mgr_hk(refresh: false)
    { matched: mgr_science?(sample), sample: sample, expected_mode: 'SCIENCE' }
  end
end

def wait_for_gps_orbit_nominal_baseline(timeout)
  wait_until(timeout, 0.8) do
    sample = read_gps_data(refresh: true)
    { matched: gps_orbit_nominal?(sample), sample: sample,
      expected: 'valid orbital position different from the SP008 spoof coordinates' }
  end
end

def wait_for_gps_position_spoof(timeout)
  wait_until(timeout, 0.25) do
    sample = read_gps_data(refresh: false)
    { matched: gps_spoof_position?(sample), sample: sample,
      expected_lat: GPS_SPOOF_LAT, expected_lon: GPS_SPOOF_LON, expected_alt: GPS_SPOOF_ALT }
  end
end

def wait_for_sp008_forged_delta(before_hk, counter_key, timeout)
  before_count = before_hk[:available] ? before_hk[counter_key].to_i : nil
  wait_until(timeout, 0.4) do
    hk = read_sp008_hk(refresh: true)
    matched = hk[:available] && (before_count.nil? || hk[counter_key].to_i > before_count)
    { matched: matched, before: before_hk, current: hk, counter_key: counter_key }
  end
end

def score(profile:, verdict:, attack_success:, classification:, safety_meaning:, evidence:, notes: [])
  {
    scenario: SCENARIO_ID,
    profile_id: profile[:id],
    profile_name: profile[:name],
    target_packet: profile[:target_packet],
    target_mid: format('0x%04X', profile[:target_mid]),
    verdict: verdict,
    attack_success: attack_success,
    classification: classification,
    safety_meaning: safety_meaning,
    evidence: evidence,
    notes: notes,
    completed_at: Time.now.utc.iso8601
  }
end

def classify_eps(evidence)
  return 'FAIL_ENV_EPS_LOW_BASELINE_NOT_ESTABLISHED' unless evidence[:real_low_before]
  return 'PASS_ATTACK_SUCCESS_EPS_STATE_SPOOFED' if evidence[:ground_latest_state_healthy_during_spoof] && evidence[:real_low_after_spoof_stopped]
  return 'FAIL_PAYLOAD_SPOOF_NOT_ROUTED' if evidence[:sp008_forged_count_delta_observed] && !evidence[:ground_latest_state_healthy_during_spoof]

  'FAIL_ATTACK_NO_STATE_TRUST_CHANGE'
end

def classify_adcs(evidence)
  return 'FAIL_ENV_ADCS_PASSIVE_BASELINE_NOT_ESTABLISHED' unless evidence[:real_passive_before]
  return 'PASS_ATTACK_SUCCESS_ADCS_STATE_SPOOFED' if evidence[:ground_latest_adcs_state_inertial_stable_during_spoof] && evidence[:real_passive_after_spoof_stopped]
  return 'FAIL_PAYLOAD_SPOOF_NOT_ROUTED' if evidence[:sp008_forged_count_delta_observed] && !evidence[:ground_latest_adcs_state_inertial_stable_during_spoof]

  'FAIL_ATTACK_NO_STATE_TRUST_CHANGE'
end

def classify_rw(evidence)
  return 'FAIL_ENV_RW_DISABLED_BASELINE_NOT_ESTABLISHED' unless evidence[:real_disabled_before]
  return 'PASS_ATTACK_SUCCESS_RW_STATE_SPOOFED' if evidence[:ground_latest_rw_enabled_nominal_during_spoof] && evidence[:real_disabled_after_spoof_stopped]
  return 'FAIL_PAYLOAD_SPOOF_NOT_ROUTED' if evidence[:sp008_forged_count_delta_observed] && !evidence[:ground_latest_rw_enabled_nominal_during_spoof]

  'FAIL_ATTACK_NO_STATE_TRUST_CHANGE'
end

def classify_thruster(evidence)
  return 'FAIL_ENV_THRUSTER_DISABLED_BASELINE_NOT_ESTABLISHED' unless evidence[:real_disabled_before]
  return 'PASS_ATTACK_SUCCESS_THRUSTER_STATE_SPOOFED' if evidence[:ground_latest_thruster_enabled_during_spoof] && evidence[:real_disabled_after_spoof_stopped]
  return 'FAIL_PAYLOAD_SPOOF_NOT_ROUTED' if evidence[:sp008_forged_count_delta_observed] && !evidence[:ground_latest_thruster_enabled_during_spoof]

  'FAIL_ATTACK_NO_STATE_TRUST_CHANGE'
end

def classify_torquer(evidence)
  return 'FAIL_ENV_TORQUER_DISABLED_BASELINE_NOT_ESTABLISHED' unless evidence[:real_disabled_before]
  return 'PASS_ATTACK_SUCCESS_TORQUER_STATE_SPOOFED' if evidence[:ground_latest_torquer_active_during_spoof] && evidence[:real_disabled_after_spoof_stopped]
  return 'FAIL_PAYLOAD_SPOOF_NOT_ROUTED' if evidence[:sp008_forged_count_delta_observed] && !evidence[:ground_latest_torquer_active_during_spoof]

  'FAIL_ATTACK_NO_STATE_TRUST_CHANGE'
end

def classify_mgr(evidence)
  return 'FAIL_ENV_MGR_SAFE_BASELINE_NOT_ESTABLISHED' unless evidence[:real_safe_before]
  return 'PASS_ATTACK_SUCCESS_MGR_STATE_SPOOFED' if evidence[:ground_latest_mgr_science_during_spoof] && evidence[:real_safe_after_spoof_stopped]
  return 'FAIL_PAYLOAD_SPOOF_NOT_ROUTED' if evidence[:sp008_forged_count_delta_observed] && !evidence[:ground_latest_mgr_science_during_spoof]

  'FAIL_ATTACK_NO_STATE_TRUST_CHANGE'
end

def classify_gps(evidence)
  return 'FAIL_ENV_GPS_ORBIT_BASELINE_NOT_ESTABLISHED' unless evidence[:real_orbit_before]
  return 'PASS_ATTACK_SUCCESS_GPS_STATE_SPOOFED' if evidence[:ground_latest_gps_position_spoofed_during_attack] && evidence[:real_orbit_after_spoof_stopped]
  return 'FAIL_PAYLOAD_SPOOF_NOT_ROUTED' if evidence[:sp008_forged_count_delta_observed] && !evidence[:ground_latest_gps_position_spoofed_during_attack]

  'FAIL_ATTACK_NO_STATE_TRUST_CHANGE'
end

def run_eps_profile(profile)
  pre_stop = sp008_stop_spoof
  sleep(0.8)
  initial_sp008 = read_sp008_hk
  low_setup = set_eps_low_power
  baseline = wait_for_eps_low_baseline(BASELINE_TIMEOUT_SECONDS)
  before_sp008 = read_sp008_hk

  start = sp008_start_profile(profile[:id])
  legacy_fallback = nil
  unless start[:ok]
    legacy_fallback = sp008_start_eps_legacy
    start = legacy_fallback
  end
  forged_delta = wait_for_sp008_forged_delta(before_sp008, :forged_eps_hk_count, SPOOF_TIMEOUT_SECONDS)
  during_spoof = wait_for_eps_healthy_spoof(SPOOF_TIMEOUT_SECONDS)
  during_sp008 = read_sp008_hk

  stop = sp008_stop_spoof
  sleep(0.8)
  after_stop = wait_for_eps_low_baseline(RESTORE_TIMEOUT_SECONDS)
  final_sp008 = read_sp008_hk

  evidence = {
    target_packet: profile[:target_packet],
    target_mid: format('0x%04X', profile[:target_mid]),
    spoofing_app_hk_is_auxiliary_only: true,
    pre_stop_command: pre_stop,
    initial_sp008_hk: initial_sp008,
    low_setup: low_setup,
    baseline_wait: baseline,
    start_command: start,
    legacy_fallback_start_command: legacy_fallback,
    forged_delta_wait: forged_delta,
    during_spoof_wait: during_spoof,
    stop_command: stop,
    after_stop_wait: after_stop,
    before_sp008_hk: before_sp008,
    during_sp008_hk: during_sp008,
    final_sp008_hk: final_sp008,
    real_low_before: baseline[:matched] == true,
    sp008_forged_count_delta_observed: forged_delta[:matched] == true,
    ground_latest_state_healthy_during_spoof: during_spoof[:matched] == true,
    real_low_after_spoof_stopped: after_stop[:matched] == true
  }

  classification = classify_eps(evidence)
  attack_success = classification == 'PASS_ATTACK_SUCCESS_EPS_STATE_SPOOFED'
  score(
    profile: profile,
    verdict: attack_success ? 'PASS' : 'FAIL',
    attack_success: attack_success,
    classification: classification,
    safety_meaning: attack_success ?
      'The real EPS was low power, but the latest ground-visible GENERIC_EPS_HK_TLM state became healthy while SP008 spoofed MID 0x091A, then returned low after spoofing stopped.' :
      'The verifier did not prove that the ground-visible EPS world model was overwritten by forged EPS housekeeping.',
    evidence: evidence,
    notes: [
      'PASS does not depend on SP008_HK_TLM values; SP008_HK_TLM only helps prove the malicious app transmitted packets.',
      "Low threshold: BATT_VOLTAGE < #{LOW_BATT_THRESHOLD}; healthy thresholds: BATT_VOLTAGE >= #{HEALTHY_BATT_THRESHOLD}, SA_VOLTAGE >= #{HEALTHY_SA_THRESHOLD}."
    ]
  )
end

def run_adcs_profile(profile)
  pre_stop = sp008_stop_spoof
  sleep(0.8)
  initial_sp008 = read_sp008_hk
  baseline_setup = set_adcs_passive
  baseline = wait_for_adcs_passive_baseline(BASELINE_TIMEOUT_SECONDS)
  before_sp008 = read_sp008_hk

  start = sp008_start_profile(profile[:id])
  forged_delta = wait_for_sp008_forged_delta(before_sp008, :forged_adcs_gnc_count, SPOOF_TIMEOUT_SECONDS)
  during_spoof = wait_for_adcs_inertial_stable_spoof(SPOOF_TIMEOUT_SECONDS)
  during_sp008 = read_sp008_hk

  stop = sp008_stop_spoof
  sleep(0.8)
  restore_setup = set_adcs_passive
  after_stop = wait_for_adcs_passive_baseline(RESTORE_TIMEOUT_SECONDS)
  final_sp008 = read_sp008_hk

  evidence = {
    target_packet: profile[:target_packet],
    target_mid: format('0x%04X', profile[:target_mid]),
    spoofing_app_hk_is_auxiliary_only: true,
    pre_stop_command: pre_stop,
    initial_sp008_hk: initial_sp008,
    baseline_setup: baseline_setup,
    baseline_wait: baseline,
    start_command: start,
    forged_delta_wait: forged_delta,
    during_spoof_wait: during_spoof,
    stop_command: stop,
    restore_setup: restore_setup,
    after_stop_wait: after_stop,
    before_sp008_hk: before_sp008,
    during_sp008_hk: during_sp008,
    final_sp008_hk: final_sp008,
    real_passive_before: baseline[:matched] == true,
    sp008_forged_count_delta_observed: forged_delta[:matched] == true,
    ground_latest_adcs_state_inertial_stable_during_spoof: during_spoof[:matched] == true,
    real_passive_after_spoof_stopped: after_stop[:matched] == true
  }

  classification = classify_adcs(evidence)
  attack_success = classification == 'PASS_ATTACK_SUCCESS_ADCS_STATE_SPOOFED'
  score(
    profile: profile,
    verdict: attack_success ? 'PASS' : 'FAIL',
    attack_success: attack_success,
    classification: classification,
    safety_meaning: attack_success ?
      'The real ADCS was passive, but the latest ground-visible GENERIC_ADCS_GNC state became inertial/stable while SP008 spoofed MID 0x0943, then returned passive after spoofing stopped.' :
      'The verifier did not prove that the ground-visible ADCS world model was overwritten by forged ADCS GNC telemetry.',
    evidence: evidence,
    notes: [
      'PASS does not depend on SP008_HK_TLM values; SP008_HK_TLM only helps prove the malicious app transmitted packets.',
      "Stable spoof criteria: MODE INERTIAL, Q_VALID true, QBN approximately [0,0,0,1], |WBN_X/Y/Z| <= #{ADCS_ZERO_RATE_THRESHOLD}."
    ]
  )
end

def run_state_spoof_profile(profile:, baseline_setup_method:, baseline_wait_method:, spoof_wait_method:,
                            restore_setup_method:, restore_wait_method:, counter_key:, evidence_keys:,
                            classify_method:, safety_success:, safety_failure:, notes:)
  pre_stop = sp008_stop_spoof
  sleep(0.8)
  initial_sp008 = read_sp008_hk
  baseline_setup = send(baseline_setup_method)
  baseline = send(baseline_wait_method, BASELINE_TIMEOUT_SECONDS)
  before_sp008 = read_sp008_hk

  start = sp008_start_profile(profile[:id])
  forged_delta = wait_for_sp008_forged_delta(before_sp008, counter_key, SPOOF_TIMEOUT_SECONDS)
  during_spoof = send(spoof_wait_method, SPOOF_TIMEOUT_SECONDS)
  during_sp008 = read_sp008_hk

  stop = sp008_stop_spoof
  sleep(0.8)
  restore_setup = restore_setup_method ? send(restore_setup_method) : nil
  after_stop = send(restore_wait_method, RESTORE_TIMEOUT_SECONDS)
  final_sp008 = read_sp008_hk

  evidence = {
    target_packet: profile[:target_packet],
    target_mid: format('0x%04X', profile[:target_mid]),
    spoofing_app_hk_is_auxiliary_only: true,
    pre_stop_command: pre_stop,
    initial_sp008_hk: initial_sp008,
    baseline_setup: baseline_setup,
    baseline_wait: baseline,
    start_command: start,
    forged_delta_wait: forged_delta,
    during_spoof_wait: during_spoof,
    stop_command: stop,
    restore_setup: restore_setup,
    after_stop_wait: after_stop,
    before_sp008_hk: before_sp008,
    during_sp008_hk: during_sp008,
    final_sp008_hk: final_sp008,
    sp008_forged_count_delta_observed: forged_delta[:matched] == true
  }
  evidence[evidence_keys[:before]] = baseline[:matched] == true
  evidence[evidence_keys[:during]] = during_spoof[:matched] == true
  evidence[evidence_keys[:after]] = after_stop[:matched] == true

  classification = send(classify_method, evidence)
  attack_success = classification.start_with?('PASS_ATTACK_SUCCESS')
  score(
    profile: profile,
    verdict: attack_success ? 'PASS' : 'FAIL',
    attack_success: attack_success,
    classification: classification,
    safety_meaning: attack_success ? safety_success : safety_failure,
    evidence: evidence,
    notes: notes
  )
end

def run_rw_profile(profile)
  run_state_spoof_profile(
    profile: profile,
    baseline_setup_method: :set_rw_disabled,
    baseline_wait_method: :wait_for_rw_disabled_baseline,
    spoof_wait_method: :wait_for_rw_enabled_nominal_spoof,
    restore_setup_method: :set_rw_disabled,
    restore_wait_method: :wait_for_rw_disabled_baseline,
    counter_key: :forged_rw_hk_count,
    evidence_keys: {
      before: :real_disabled_before,
      during: :ground_latest_rw_enabled_nominal_during_spoof,
      after: :real_disabled_after_spoof_stopped
    },
    classify_method: :classify_rw,
    safety_success: 'The real reaction wheels were disabled, but the latest ground-visible GENRW_HK_TLM_T state showed all wheels enabled with nominal momentum while SP008 spoofed MID 0x0993, then returned disabled after spoofing stopped.',
    safety_failure: 'The verifier did not prove that the ground-visible reaction wheel world model was overwritten by forged reaction wheel housekeeping.',
    notes: [
      'PASS evidence comes from GENERIC_REACTION_WHEEL GENRW_HK_TLM_T, not SP008_HK_TLM.',
      'If the GENERIC_REACTION_WHEEL packet is stale because another COSMOS dictionary owns MID 0x0993, the verifier reads the same real MID through CFS SP006_RW_HK_TLM and records source_target/source_packet in evidence.',
      "Nominal spoof criteria: all DEVICE_ENABLED_RW* true and |MOMENTUM_NMS_*| <= #{RW_NOMINAL_MOMENTUM_THRESHOLD}."
    ]
  )
end

def run_thruster_profile(profile)
  run_state_spoof_profile(
    profile: profile,
    baseline_setup_method: :set_thruster_disabled,
    baseline_wait_method: :wait_for_thruster_disabled_baseline,
    spoof_wait_method: :wait_for_thruster_enabled_spoof,
    restore_setup_method: :set_thruster_disabled,
    restore_wait_method: :wait_for_thruster_disabled_baseline,
    counter_key: :forged_thruster_hk_count,
    evidence_keys: {
      before: :real_disabled_before,
      during: :ground_latest_thruster_enabled_during_spoof,
      after: :real_disabled_after_spoof_stopped
    },
    classify_method: :classify_thruster,
    safety_success: 'The real thruster app was disabled, but the latest ground-visible GENERIC_THRUSTER_HK_TLM state showed enabled/healthy while SP008 spoofed MID 0x08EA, then returned disabled after spoofing stopped.',
    safety_failure: 'The verifier did not prove that the ground-visible thruster world model was overwritten by forged thruster housekeeping.',
    notes: [
      'PASS evidence comes from GENERIC_THRUSTER GENERIC_THRUSTER_HK_TLM, not SP008_HK_TLM.',
      'If the GENERIC_THRUSTER packet is stale because another COSMOS dictionary owns MID 0x08EA, the verifier reads the same real MID through CFS SP006_THRUSTER_HK_TLM and records source_target/source_packet in evidence.'
    ]
  )
end

def run_torquer_profile(profile)
  run_state_spoof_profile(
    profile: profile,
    baseline_setup_method: :set_torquer_disabled,
    baseline_wait_method: :wait_for_torquer_disabled_baseline,
    spoof_wait_method: :wait_for_torquer_active_spoof,
    restore_setup_method: :set_torquer_disabled,
    restore_wait_method: :wait_for_torquer_disabled_baseline,
    counter_key: :forged_torquer_hk_count,
    evidence_keys: {
      before: :real_disabled_before,
      during: :ground_latest_torquer_active_during_spoof,
      after: :real_disabled_after_spoof_stopped
    },
    classify_method: :classify_torquer,
    safety_success: 'The real torquer app was disabled, but the latest ground-visible GENERIC_TORQUER_HK_TLM_T state showed enabled torquers with nonzero percent-on commands while SP008 spoofed MID 0x093A, then returned disabled after spoofing stopped.',
    safety_failure: 'The verifier did not prove that the ground-visible torquer world model was overwritten by forged torquer housekeeping.',
    notes: ['PASS evidence comes from GENERIC_TORQUER GENERIC_TORQUER_HK_TLM_T, not SP008_HK_TLM.']
  )
end

def run_mgr_profile(profile)
  run_state_spoof_profile(
    profile: profile,
    baseline_setup_method: :set_mgr_safe,
    baseline_wait_method: :wait_for_mgr_safe_baseline,
    spoof_wait_method: :wait_for_mgr_science_spoof,
    restore_setup_method: :set_mgr_safe,
    restore_wait_method: :wait_for_mgr_safe_baseline,
    counter_key: :forged_mgr_hk_count,
    evidence_keys: {
      before: :real_safe_before,
      during: :ground_latest_mgr_science_during_spoof,
      after: :real_safe_after_spoof_stopped
    },
    classify_method: :classify_mgr,
    safety_success: 'The real manager state was SAFE, but the latest ground-visible MGR_HK_TLM state showed SCIENCE with science regions enabled while SP008 spoofed MID 0x08F8, then returned SAFE after spoofing stopped.',
    safety_failure: 'The verifier did not prove that the ground-visible manager mode/world model was overwritten by forged MGR housekeeping.',
    notes: ['PASS evidence comes from MGR MGR_HK_TLM, not SP008_HK_TLM.']
  )
end

def run_gps_profile(profile)
  run_state_spoof_profile(
    profile: profile,
    baseline_setup_method: :capture_gps_orbit_baseline,
    baseline_wait_method: :wait_for_gps_orbit_nominal_baseline,
    spoof_wait_method: :wait_for_gps_position_spoof,
    restore_setup_method: nil,
    restore_wait_method: :wait_for_gps_orbit_nominal_baseline,
    counter_key: :forged_gps_data_count,
    evidence_keys: {
      before: :real_orbit_before,
      during: :ground_latest_gps_position_spoofed_during_attack,
      after: :real_orbit_after_spoof_stopped
    },
    classify_method: :classify_gps,
    safety_success: 'The real GPS position was a different nominal orbit state, but the latest ground-visible NOVATEL_OEM615_DATA_TLM position became the SP008 spoof coordinates while SP008 spoofed MID 0x0871, then returned to non-spoof orbital data after spoofing stopped.',
    safety_failure: 'The verifier did not prove that the ground-visible GPS world model was overwritten by forged NOVATEL_OEM615 data telemetry.',
    notes: [
      'PASS evidence comes from NOVATEL_OEM615 NOVATEL_OEM615_DATA_TLM, not SP008_HK_TLM.',
      "Spoof position: lat #{GPS_SPOOF_LAT}, lon #{GPS_SPOOF_LON}, alt #{GPS_SPOOF_ALT} m."
    ]
  )
end

def select_profiles
  return PROFILES if SELECTED_PROFILE_IDS.empty?

  wanted = SELECTED_PROFILE_IDS.map(&:upcase)
  selected = PROFILES.select do |profile|
    wanted.include?(profile[:id].to_s) || wanted.include?(profile[:name].upcase)
  end
  missing = SELECTED_PROFILE_IDS.reject do |entry|
    PROFILES.any? { |profile| profile[:id].to_s == entry || profile[:name].casecmp?(entry) }
  end
  raise SkipProfile.new('FAIL_UNKNOWN_PROFILE', "Unknown SP008 profile(s): #{missing.join(', ')}") unless missing.empty?

  selected
end

def run_profile(profile)
  started = Time.now
  send(profile[:run], profile).merge(duration_seconds: Time.now - started)
rescue SkipProfile => error
  score(
    profile: profile,
    verdict: 'SKIP',
    attack_success: false,
    classification: error.classification,
    safety_meaning: error.message,
    evidence: { error: error.message },
    notes: []
  ).merge(duration_seconds: Time.now - started)
rescue Exception => error
  score(
    profile: profile,
    verdict: 'FAIL',
    attack_success: false,
    classification: 'FAIL_VERIFIER_ERROR',
    safety_meaning: 'Verifier error prevented a security-relevant conclusion.',
    evidence: { error_class: error.class.to_s, error: error.message, backtrace: error.backtrace&.first(8) },
    notes: []
  ).merge(duration_seconds: Time.now - started)
end

def summarize(scores, routes, initial_sp008)
  passed = scores.count { |score| score[:verdict] == 'PASS' }
  failed = scores.count { |score| score[:verdict] == 'FAIL' }
  skipped = scores.count { |score| score[:verdict] == 'SKIP' }
  {
    scenario: SCENARIO_ID,
    name: SCENARIO_NAME,
    generated_at: Time.now.utc.iso8601,
    report_root: REPORT_ROOT,
    attack_description: ATTACK_DESCRIPTION,
    result: failed.zero? ? 'PASS' : 'FAIL',
    profiles_total: scores.length,
    profiles_passed: passed,
    profiles_failed: failed,
    profiles_skipped: skipped,
    routes: routes,
    initial_sp008_hk: initial_sp008,
    profiles: scores.map do |score|
      {
        profile_id: score[:profile_id],
        profile_name: score[:profile_name],
        target_packet: score[:target_packet],
        target_mid: score[:target_mid],
        verdict: score[:verdict],
        attack_success: score[:attack_success],
        classification: score[:classification],
        safety_meaning: score[:safety_meaning]
      }
    end
  }
end

FileUtils.mkdir_p(REPORT_ROOT)
started = Time.now.utc
routes = ensure_routes
initial_sp008 = read_sp008_hk
selected = select_profiles

scores = selected.map do |profile|
  result = run_profile(profile)
  write_json(File.join(REPORT_ROOT, 'profiles', profile[:name], 'score.json'), result)
  puts "#{profile[:name]}: #{result[:verdict]} - #{result[:classification]}"
  result
end

summary = summarize(scores, routes, initial_sp008).merge(started_at: started.iso8601)
write_json(File.join(REPORT_ROOT, 'summary.json'), summary)

puts "#{SCENARIO_ID} #{SCENARIO_NAME}: #{summary[:result]}"
puts "Profiles: #{summary[:profiles_passed]}/#{summary[:profiles_total]} PASS"
puts "Report: #{REPORT_ROOT}"
puts JSON.pretty_generate(summary)

exit(summary[:result] == 'PASS' ? 0 : 1)
