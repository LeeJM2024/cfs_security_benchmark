require 'json'
require 'fileutils'
require 'open3'
require 'socket'
require 'time'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

SCENARIO_ID = 'SP002'
SCENARIO_NAME = 'Malformed TC parser and command handler input'
MODE = ENV.fetch('SP002_MODE', 'safe')
CONFIRM_HAZARD = ENV.fetch('SP002_CONFIRM_HAZARD', 'NO')
CI_HOST = ENV.fetch('SP002_CI_HOST', 'sc01-nos-fsw')
CI_PORT = ENV.fetch('SP002_CI_PORT', '5012')
SENDER = ENV.fetch('SP002_SENDER', '/tmp/sp002_send_malformed_tc.py')
PROFILE_IDS = ENV.fetch('SP002_PROFILE_IDS', '').split(',').map(&:strip).reject(&:empty?)
TARGET_FILTER = ENV.fetch('SP002_TARGET', '').strip
TAG_FILTERS = ENV.fetch('SP002_TAGS', '').split(',').map(&:strip).reject(&:empty?)
OBSERVE_WINDOW = ENV.fetch('SP002_OBSERVE_WINDOW', ENV.fetch('SP002_WAIT_AFTER_SEND', '5.0')).to_f
OBSERVE_INTERVAL = ENV.fetch('SP002_OBSERVE_INTERVAL', '0.5').to_f
BASELINE_MARKER = ENV.fetch('SP002_BASELINE_MARKER', 'YES') != 'NO'
BASELINE_WAIT = ENV.fetch('SP002_BASELINE_WAIT', '2.0').to_f
RECOVERY_WAIT = ENV.fetch('SP002_RECOVERY_WAIT', '6.0').to_f
CONTROL_WAIT = ENV.fetch('SP002_CONTROL_WAIT', '10.0').to_f
REPORT_ROOT = ENV.fetch('SP002_REPORT_DIR', "/tmp/sp002_malformed_tc_results/#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}")

TO_LAB_CMD_MID = 0x18E8
TO_LAB_ADD_PACKET_CC = 6
CFE_ES_HK_TLM_MID = 0x0800
CFE_EVS_LONG_EVENT_MID = 0x0808
CFE_EVS_SHORT_EVENT_MID = 0x0809
CI_HK_TLM_MID = 0x080C

ATTACK_DESCRIPTION = {
  attack_entry: 'External attacker sends raw UDP telemetry-command datagrams directly to CI/CI_LAB',
  affected_components: 'CI_LAB, cFE message validation, Software Bus routing, command handlers for CFE_ES, FM, DS, LC, SC, SCH, TO_LAB, ADCS, sensors, actuators, radio, GNSS, and EPS components',
  cps_type: 'Malformed telecommand parser input / unauthorized external command injection',
  security_consequence: 'Malformed or unauthorized TC may be accepted, rejected with observable state changes, disrupt telemetry, alter command counters, or reach command handlers that should only process authenticated ground commands',
  recovery_strategy: 'Stop malformed traffic, verify normal ground command/telemetry loop with CFE_ES NOOP/HK, and use normal operational commands to restore any changed app or component state',
  nos3_cfs_injection: 'Raw UDP datagram to CI_LAB port 5012; CI_LAB passes accepted-size datagrams to CFE_SB_TransmitBuffer'
}

TARGET_COUNTERS = {
  'CFE_ES' => [['CFS', 'CFE_ES_HKPACKET', 'CMDCOUNTER'], ['CFS', 'CFE_ES_HKPACKET', 'ERRCOUNTER']],
  'FM' => [['CFS', 'FM_HOUSEKEEPINGPKT', 'COMMANDCOUNTER'], ['CFS', 'FM_HOUSEKEEPINGPKT', 'COMMANDERRCOUNTER']],
  'DS' => [['CFS', 'DS_HKPACKET', 'CMDACCEPTEDCOUNTER'], ['CFS', 'DS_HKPACKET', 'CMDREJECTEDCOUNTER']],
  'LC' => [['CFS', 'LC_HKPACKET', 'CMDCOUNT'], ['CFS', 'LC_HKPACKET', 'CMDERRCOUNT']],
  'SC' => [['CFS', 'SC_HKTLM', 'CMDCTR'], ['CFS', 'SC_HKTLM', 'CMDERRCTR']],
  'SCH' => [['CFS', 'SCH_HKPACKET', 'CMDCOUNTER'], ['CFS', 'SCH_HKPACKET', 'ERRCOUNTER']],
  'TO_LAB' => [['CFS', 'TO_HKPACKET', 'CMDCOUNTER'], ['CFS', 'TO_HKPACKET', 'ERRCOUNTER']],
  'TO' => [['CFS', 'TO_HKPACKET', 'CMDCOUNTER'], ['CFS', 'TO_HKPACKET', 'ERRCOUNTER']],
  'GENERIC_ADCS' => [['GENERIC_ADCS', 'GENERIC_ADCS_HK_TLM', 'CMD_COUNT'], ['GENERIC_ADCS', 'GENERIC_ADCS_HK_TLM', 'CMD_ERR_COUNT']],
  'GENERIC_THRUSTER' => [['GENERIC_THRUSTER', 'GENERIC_THRUSTER_HK_TLM', 'CMD_COUNT'], ['GENERIC_THRUSTER', 'GENERIC_THRUSTER_HK_TLM', 'CMD_ERR_COUNT']],
  'GENERIC_RADIO' => [['GENERIC_RADIO', 'GENERIC_RADIO_HK_TLM', 'CMD_COUNT'], ['GENERIC_RADIO', 'GENERIC_RADIO_HK_TLM', 'CMD_ERR_COUNT']],
  'NOVATEL_OEM615' => [['NOVATEL_OEM615', 'NOVATEL_OEM615_HK_TLM', 'CMD_COUNT'], ['NOVATEL_OEM615', 'NOVATEL_OEM615_HK_TLM', 'CMD_ERR_COUNT']],
  'GENERIC_IMU' => [['GENERIC_IMU', 'GENERIC_IMU_HK_TLM', 'CMD_COUNT'], ['GENERIC_IMU', 'GENERIC_IMU_HK_TLM', 'CMD_ERR_COUNT']],
  'GENERIC_MAG' => [['GENERIC_MAG', 'GENERIC_MAG_HK_TLM', 'CMD_COUNT'], ['GENERIC_MAG', 'GENERIC_MAG_HK_TLM', 'CMD_ERR_COUNT']],
  'GENERIC_CSS' => [['GENERIC_CSS', 'GENERIC_CSS_HK_TLM', 'CMD_COUNT'], ['GENERIC_CSS', 'GENERIC_CSS_HK_TLM', 'CMD_ERR_COUNT']],
  'GENERIC_FSS' => [['GENERIC_FSS', 'GENERIC_FSS_HK_TLM', 'CMD_COUNT'], ['GENERIC_FSS', 'GENERIC_FSS_HK_TLM', 'CMD_ERR_COUNT']],
  'GENERIC_STAR_TRACKER' => [['GENERIC_STAR_TRACKER', 'GENERIC_STAR_TRACKER_HK_TLM', 'CMD_COUNT'], ['GENERIC_STAR_TRACKER', 'GENERIC_STAR_TRACKER_HK_TLM', 'CMD_ERR_COUNT']],
  'GENERIC_EPS' => [['GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'CMD_COUNT'], ['GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'CMD_ERR_COUNT']],
  'GENERIC_RW' => [['GENERIC_REACTION_WHEEL', 'GENRW_HK_TLM_T', 'COMMAND_COUNT'], ['GENERIC_REACTION_WHEEL', 'GENRW_HK_TLM_T', 'ERROR_COUNT']],
  'GENERIC_TORQUER' => [['GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'CMD_COUNT'], ['GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'CMD_ERR_COUNT']]
}

STATE_ITEMS = {
  'GENERIC_ADCS' => [['GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'MODE'], ['GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'MOMENTUM_MANAGEMENT']],
  'GENERIC_EPS' => [['GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'SWITCH_0_STATE']],
  'GENERIC_THRUSTER' => [['GENERIC_THRUSTER', 'GENERIC_THRUSTER_HK_TLM', 'DEVICE_ENABLED']],
  'GENERIC_TORQUER' => [['GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'DEVICE_ENABLED']],
  'GENERIC_RW' => [['GENERIC_REACTION_WHEEL', 'GENRW_HK_TLM_T', 'DEVICE_ENABLED_RW0']],
  'DS' => [['CFS', 'DS_HKPACKET', 'APPENABLESTATE']],
  'LC' => [['CFS', 'LC_HKPACKET', 'CURRENTLCSTATE']],
  'SC' => [['CFS', 'SC_HKTLM', 'NUMRTSACTIVE'], ['CFS', 'SC_HKTLM', 'RTSACTIVECTR']]
}

GENERAL_TLM = [
  ['CFS', 'CFE_EVS_TLMPKT', 'MESSAGESENDCOUNTER'],
  ['CFS', 'CFE_EVS_TLMPKT', 'COMMANDERRCOUNTER'],
  ['CFS', 'CI_HKPACKET', 'CCSDS_SEQUENCE'],
  ['CFS', 'CFE_EVS_PACKET', 'MESSAGE'],
  ['CFS', 'CFE_EVS_PACKET', 'PACKETID_APPNAME'],
  ['CFS', 'CFE_EVS_PACKET', 'PACKETID_EVENTID']
]


APP_ALIASES = {
  'CFE_ES' => ['CFE_ES'],
  'FM' => ['FM'],
  'DS' => ['DS'],
  'LC' => ['LC'],
  'SC' => ['SC'],
  'SCH' => ['SCH'],
  'TO_LAB' => ['TO', 'TO_LAB', 'TO_LAB_APP'],
  'TO' => ['TO', 'TO_LAB', 'TO_LAB_APP'],
  'GENERIC_ADCS' => ['ADCS', 'GENERIC_ADCS'],
  'GENERIC_THRUSTER' => ['THRUSTER', 'GENERIC_THRUSTER'],
  'GENERIC_RADIO' => ['RADIO', 'GENERIC_RADIO', 'RADIO.GENERIC_RADIO'],
  'NOVATEL_OEM615' => ['NAV', 'NOVATEL_OEM615'],
  'GENERIC_IMU' => ['IMU', 'GENERIC_IMU'],
  'GENERIC_MAG' => ['MAG', 'GENERIC_MAG'],
  'GENERIC_CSS' => ['CSS', 'GENERIC_CSS'],
  'GENERIC_FSS' => ['FSS', 'GENERIC_FSS'],
  'GENERIC_STAR_TRACKER' => ['ST', 'STAR_TRACKER', 'GENERIC_STAR_TRACKER'],
  'GENERIC_EPS' => ['EPS', 'GENERIC_EPS'],
  'GENERIC_RW' => ['RW', 'GENERIC_RW', 'GENERIC_REACTION_WHEEL'],
  'GENERIC_TORQUER' => ['TORQUER', 'GENERIC_TORQUER']
}

class Sp002Skip < StandardError; end

def hazard_mode?(mode)
  ['hazardous', 'short-all', 'all'].include?(mode)
end

def ensure_allowed_mode!
  valid = ['safe', 'hazardous', 'short-all', 'all']
  raise "Invalid SP002_MODE=#{MODE.inspect}; expected one of #{valid.join(', ')}" unless valid.include?(MODE)
  return unless hazard_mode?(MODE)
  return if CONFIRM_HAZARD == 'YES'

  raise "SP002_MODE=#{MODE} includes hazardous profiles. Set SP002_CONFIRM_HAZARD=YES to run it."
end

def run_cmd(argv, env = {})
  stdout, stderr, status = Open3.capture3(env, *argv)
  {
    argv: argv,
    exitstatus: status.exitstatus,
    success: status.success?,
    stdout: stdout,
    stderr: stderr
  }
end

def json_cmd(argv, env = {})
  result = run_cmd(argv, env)
  raise "Command failed: #{argv.join(' ')}\n#{result[:stderr]}" unless result[:success]

  parsed = JSON.parse(result[:stdout])
  [parsed, result]
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
  UDPSocket.open { |socket| socket.send(packet, 0, CI_HOST, CI_PORT) }
  { ok: true, host: CI_HOST, port: CI_PORT, bytes: packet.bytesize, checksum_result: cfe_checksum(packet) }
rescue Exception => error
  { ok: false, host: CI_HOST, port: CI_PORT, error_class: error.class.to_s, error: error.message }
end

def add_to_lab_route(mid)
  # TO_LAB AddPacket: stream MID, destination index 0, no flags, bounded queue.
  payload = [mid & 0xFFFFFFFF].pack('V') + [0, 0, 32, 0].pack('C C C C')
  send_udp(command_packet(TO_LAB_CMD_MID, TO_LAB_ADD_PACKET_CC, payload)).merge(mid: format('0x%04X', mid))
end

def send_sender_profile(profile_id)
  json_cmd(
    [
      '/usr/bin/python3', SENDER, '--mode', 'all', 'send', profile_id,
      '--host', CI_HOST, '--port', CI_PORT, '--json'
    ]
  ).first
end

def reassert_observation_routes
  output = send_sender_profile('to_lab_output_enable_valid_shape')
  sleep(0.3)
  routes = [CFE_ES_HK_TLM_MID, CFE_EVS_LONG_EVENT_MID, CFE_EVS_SHORT_EVENT_MID, CI_HK_TLM_MID].map do |mid|
    route = add_to_lab_route(mid)
    sleep(0.15)
    route
  end
  { output_enable: output, routes: routes }
rescue Exception => error
  { error_class: error.class.to_s, error: error.message }
end

def request_es_hk
  cmd('CFS CFE_ES_SEND_HK')
  { ok: true, command: 'CFS CFE_ES_SEND_HK' }
rescue Exception => error
  { ok: false, command: 'CFS CFE_ES_SEND_HK', error_class: error.class.to_s, error: error.message }
end

def wait_for_es_noop_observation(before_counter, before_event, timeout = CONTROL_WAIT)
  deadline = Time.now + timeout
  last_counter = before_counter
  last_event = before_event
  until Time.now >= deadline
    last_counter = tlm_read('CFS', 'CFE_ES_HKPACKET', 'CMDCOUNTER')
    last_event = tlm_read('CFS', 'CFE_EVS_PACKET', 'MESSAGE')
    before_value = before_counter[:available] ? before_counter[:value].to_i : nil
    after_value = last_counter[:available] ? last_counter[:value].to_i : nil
    counter_advanced = before_value && after_value && after_value > before_value
    noop_event = last_event[:available] && before_event[:value] != last_event[:value] && last_event[:value].to_s.include?('No-op')
    return { matched: true, counter_advanced: counter_advanced, noop_event: noop_event, counter: last_counter, event: last_event } if counter_advanced || noop_event

    sleep(0.5)
  end
  { matched: false, counter: last_counter, event: last_event }
end

def establish_raw_ci_control
  attempts = []
  2.times do |attempt|
    routes = reassert_observation_routes
    request = request_es_hk
    sleep(0.5)
    before_counter = tlm_read('CFS', 'CFE_ES_HKPACKET', 'CMDCOUNTER')
    before_event = tlm_read('CFS', 'CFE_EVS_PACKET', 'MESSAGE')
    noop = send_sender_profile('cfe_es_noop_valid_shape')
    observation = wait_for_es_noop_observation(before_counter, before_event)
    attempts << { attempt: attempt + 1, routes: routes, request_es_hk: request, before_counter: before_counter,
                  before_event: before_event, noop: noop, observation: observation }
    return { ready: true, attempts: attempts } if observation[:matched]
  end
  { ready: false, attempts: attempts }
end

def scalar(value)
  return value if value.is_a?(Numeric)
  text = value.to_s.strip
  return text.to_i if text =~ /\A[-+]?\d+\z/
  return text.to_f if text =~ /\A[-+]?\d+\.\d+\z/
  text
end

def tlm_read(target, packet, item)
  value = tlm("#{target} #{packet} #{item}")
  { available: true, target: target, packet: packet, item: item, value: scalar(value) }
rescue Exception => error
  { available: false, target: target, packet: packet, item: item, error: error.message }
end

def read_items(items)
  items.map { |target, packet, item| tlm_read(target, packet, item) }
end

def snapshot(profile)
  target = profile['target'].to_s
  {
    time_utc: Time.now.utc.iso8601,
    general: read_items(GENERAL_TLM),
    target: read_items(TARGET_COUNTERS.fetch(target, [])),
    state: read_items(STATE_ITEMS.fetch(target, []))
  }
end

def values_by_key(readings)
  result = {}
  readings.each do |entry|
    next unless entry[:available]
    result[[entry[:target], entry[:packet], entry[:item]].join(' ')] = entry[:value]
  end
  result
end

def numeric_delta(before, after)
  deltas = {}
  before.each do |key, before_value|
    next unless before_value.is_a?(Numeric)
    after_value = after[key]
    next unless after_value.is_a?(Numeric)
    delta = after_value - before_value
    deltas[key] = delta if delta != 0
  end
  deltas
end

def max_numeric_delta(before, after_samples, section)
  before_values = values_by_key(before[section])
  deltas = {}
  after_samples.each do |sample|
    numeric_delta(before_values, values_by_key(sample[section])).each do |key, delta|
      current = deltas[key]
      deltas[key] = delta if current.nil? || delta.abs > current.abs
    end
  end
  deltas
end

def changed_values_across(before, after_samples, section)
  before_values = values_by_key(before[section])
  changes = {}
  after_samples.each do |sample|
    after_values = values_by_key(sample[section])
    before_values.each do |key, before_value|
      next if changes.key?(key)
      next unless after_values.key?(key)
      after_value = after_values[key]
      changes[key] = { before: before_value, after: after_value } if before_value != after_value
    end
  end
  changes
end

def collect_after_snapshots(profile)
  samples = []
  window = [OBSERVE_WINDOW, OBSERVE_INTERVAL].max
  deadline = Time.now + window
  loop do
    sleep(OBSERVE_INTERVAL)
    samples << snapshot(profile)
    break if Time.now >= deadline
  end
  samples
end

def error_counter_key?(key)
  up = key.to_s.upcase
  up.include?('ERR') || up.include?('ERROR') || up.include?('REJECT')
end

def accepted_counter_key?(key)
  up = key.to_s.upcase
  return false if error_counter_key?(up)
  up.include?('CMD') || up.include?('COMMAND') || up.include?('ACCEPT')
end

def positive_deltas(deltas, &predicate)
  deltas.select { |key, delta| delta.is_a?(Numeric) && delta.positive? && predicate.call(key) }
end

def defense_event?(event_text)
  text = event_text.to_s.downcase
  return false if text.empty?

  needles = [
    'ci:', 'bad length', 'dropped', 'transmitbuffer() failed',
    'invalid msgid', 'no subscribers', 'msg too big', 'bad arg', 'bad argument',
    'checksum', 'invalid', 'failed', 'failure', 'cannot', "can't", 'unable', 'unsubscribe err',
    'error', 'err'
  ]
  needles.any? { |needle| text.include?(needle) }
end

def target_aliases(target)
  APP_ALIASES.fetch(target.to_s, [target.to_s]).map(&:upcase)
end

def event_app_matches_target?(target, app_name)
  app = app_name.to_s.upcase
  return false if app.empty?

  target_aliases(target).include?(app)
end

def event_message_mentions_target?(target, message)
  up = message.to_s.upcase
  target_aliases(target).any? { |alias_name| up.include?(alias_name) }
end

def target_event_record?(profile, record)
  event_app_matches_target?(profile['target'], record[:app_name]) || event_message_mentions_target?(profile['target'], record[:message])
end

def accepted_event?(profile, event_text, app_name = nil)
  text = event_text.to_s
  return false if text.empty?
  lower = text.downcase
  return false if defense_event?(text)
  return false unless event_app_matches_target?(profile['target'], app_name) || event_message_mentions_target?(profile['target'], text)

  accepted_needles = [
    'no-op command', 'changed mode', 'changed momentum', 'set inertial quaternion',
    'telemetry output enabled', 'configuration command received', 'log command received',
    'unlog command received', 'command received', 'successful', 'device enabled', 'device disabled'
  ]
  accepted_needles.any? { |needle| lower.include?(needle) }
end

def dangerous_handler_error?(profile, record)
  return false unless target_event_record?(profile, record)
  text = record[:message].to_s.downcase

  return true if profile['target'].to_s == 'GENERIC_RW' && text.include?('error writing to uart')
  return true if profile['target'].to_s == 'GENERIC_RADIO' && text.include?('send err:invalid msgid')
  false
end

def interesting_event?(event_text)
  defense_event?(event_text)
end

def infer_defense_stage(event_text, profile)
  text = event_text.to_s.downcase
  return 'command_handler_validation' if event_message_mentions_target?(profile['target'], event_text) && (text.include?('bad length') || text.include?('invalid') || text.include?('failed') || text.include?('cannot') || text.include?('error'))
  return 'ci_lab_length_gate' if text.include?('bad length') || text.include?('dropped')
  return 'software_bus_validation' if text.include?('transmitbuffer() failed') || text.include?('invalid msgid') || text.include?('no subscribers') || text.include?('msg too big')
  return 'command_handler_validation' if text.include?('checksum') || text.include?('invalid command packet length') || text.include?('invalid command code') || text.include?('error')

  pid = profile['profile_id'].to_s
  return 'ci_lab_length_gate' if pid.start_with?('ci_short_') || pid == 'ci_random_7'
  return 'software_bus_validation' if profile['target'].to_s == 'CFE_SB'
  return 'command_handler_validation' if ['command_handler', 'semantic_malformed'].include?(profile['category'].to_s)
  'unknown'
end

def event_records_from(samples)
  samples.map do |sample|
    values = values_by_key(sample[:general])
    message = values['CFS CFE_EVS_PACKET MESSAGE']
    next if message.nil?

    {
      message: message,
      app_name: values['CFS CFE_EVS_PACKET PACKETID_APPNAME'],
      event_id: values['CFS CFE_EVS_PACKET PACKETID_EVENTID'],
      time_utc: sample[:time_utc]
    }
  end.compact
end

def score_profile(profile, before, after_samples, send_meta, send_result)
  after_samples = [snapshot(profile)] if after_samples.empty?
  after = after_samples.last
  before_general = values_by_key(before[:general])
  before_event_message = before_general['CFS CFE_EVS_PACKET MESSAGE']
  after_event_records = event_records_from(after_samples)
  after_event_messages = after_event_records.map { |record| record[:message] }
  event_message = after_event_messages.last
  event_changed = after_event_messages.any? { |message| message != before_event_message }

  counter_delta = max_numeric_delta(before, after_samples, :target)
  state_changes = changed_values_across(before, after_samples, :state)
  general_delta = max_numeric_delta(before, after_samples, :general)
  accepted_counter_delta = positive_deltas(counter_delta) { |key| accepted_counter_key?(key) }
  error_counter_delta = positive_deltas(counter_delta) { |key| error_counter_key?(key) }
  evs_counter_delta = general_delta.fetch('CFS CFE_EVS_TLMPKT MESSAGESENDCOUNTER', 0).to_i

  fresh_accepted_event = after_event_records.any? do |record|
    accepted_event?(profile, record[:message], record[:app_name]) && record[:message] != before_event_message
  end
  fresh_accepted_event ||= evs_counter_delta.positive? && after_event_records.any? do |record|
    accepted_event?(profile, record[:message], record[:app_name])
  end
  dangerous_handler_error = after_event_records.any? { |record| dangerous_handler_error?(profile, record) }
  fresh_defense_event = after_event_records.any? do |record|
    defense_event?(record[:message]) && target_event_record?(profile, record) && record[:message] != before_event_message
  end
  fresh_defense_event ||= evs_counter_delta.positive? && defense_event?(before_event_message)

  evidence = {
    sender_exitstatus: send_result[:exitstatus],
    sent_bytes: send_meta['sent_bytes'],
    packet_len: send_meta['packet_len'],
    checksum_result: send_meta['checksum_result'],
    target_counter_delta: counter_delta,
    accepted_counter_delta: accepted_counter_delta,
    error_counter_delta: error_counter_delta,
    state_changes: state_changes,
    general_delta: general_delta,
    evs_message_counter_delta: evs_counter_delta,
    event_changed: event_changed,
    before_event_message: before_event_message,
    event_message: event_message,
    observed_event_messages: after_event_messages.uniq,
    observed_event_records: after_event_records.uniq,
    dangerous_handler_error: dangerous_handler_error,
    observe_window_sec: OBSERVE_WINDOW,
    observe_interval_sec: OBSERVE_INTERVAL
  }

  reasons = []
  sender_ok = send_result[:success] && send_meta['sent_bytes'].to_i == send_meta['packet_len'].to_i
  reasons << 'raw UDP sender reported full datagram send' if sender_ok

  attack_success = false
  if sender_ok && !accepted_counter_delta.empty?
    attack_success = true
    reasons << 'accepted command counter changed at target app/component'
  end
  if sender_ok && !state_changes.empty?
    attack_success = true
    reasons << 'target telemetry state changed'
  end
  if sender_ok && fresh_accepted_event
    attack_success = true
    reasons << 'accepted command event observed from cFS telemetry'
  end
  if sender_ok && dangerous_handler_error
    attack_success = true
    reasons << 'malformed input reached target handler and produced a dangerous downstream error'
  end

  defended = false
  if !attack_success && sender_ok && !error_counter_delta.empty?
    defended = true
    reasons << 'target error/reject counter changed; malformed command was rejected'
  end
  if !attack_success && sender_ok && fresh_defense_event
    defended = true
    reasons << 'CI/SB/handler defense event observed from cFS telemetry'
  end

  verdict = if attack_success
              'attack_success'
            elsif defended
              'defended'
            elsif sender_ok
              'inconclusive_no_cfs_observation'
            else
              'sender_error'
            end
  defense_record = after_event_records.find { |record| defense_event?(record[:message]) && target_event_record?(profile, record) }
  defense_stage = defended ? infer_defense_stage((defense_record && defense_record[:message]) || before_event_message, profile) : nil

  {
    scenario: SCENARIO_ID,
    profile_id: profile['profile_id'],
    title: profile['title'],
    category: profile['category'],
    target: profile['target'],
    risk: profile['risk'],
    suite: profile['suite'],
    status: attack_success ? 'PASS' : 'FAIL',
    verdict: verdict,
    defense_stage: defense_stage,
    attack_success: attack_success,
    defended: defended,
    reasons: reasons,
    expected_focus: profile['expected_focus'],
    evidence: evidence,
    before: before,
    after: after,
    after_samples: after_samples
  }
end

def write_json(path, object)
  FileUtils.mkdir_p(File.dirname(path))
  File.write(path, JSON.pretty_generate(object) + "\n")
end

def write_profile_score(report_dir, score)
  profile_dir = File.join(report_dir, 'profiles', score[:profile_id])
  FileUtils.mkdir_p(profile_dir)
  write_json(File.join(profile_dir, 'score.json'), score)
end

def write_summary(report_dir, summary, scores)
  write_json(File.join(report_dir, 'summary.json'), summary)

  lines = []
  lines << "# #{SCENARIO_ID} #{SCENARIO_NAME}"
  lines << ""
  lines << "- Mode: `#{summary[:mode]}`"
  lines << "- Result: `#{summary[:status]}`"
  lines << "- Profiles: #{summary[:pass_count]}/#{summary[:total]} PASS (#{format('%.2f', summary[:pass_rate] * 100)}%)"
  lines << "- Defended: #{summary[:defended_count]}"
  lines << "- Inconclusive: #{summary[:inconclusive_count]}"
  lines << "- Report directory: `#{report_dir}`"
  lines << ""
  lines << "## Attack Description"
  ATTACK_DESCRIPTION.each { |key, value| lines << "- #{key}: #{value}" }
  lines << ""
  lines << "## Profiles"
  scores.each do |score|
    verdict = score[:verdict] || 'error'
    stage = score[:defense_stage] ? " / #{score[:defense_stage]}" : ''
    lines << "- #{score[:profile_id]}: #{score[:status]} (#{verdict}#{stage}) - #{score[:target]} - #{score[:category]}"
  end
  lines << ""
  File.write(File.join(report_dir, 'summary.md'), lines.join("\n"))
end


def prime_event_baseline
  return { enabled: false } unless BASELINE_MARKER

  marker_meta = nil
  marker_error = nil
  begin
    marker_meta, = json_cmd(
      [
        '/usr/bin/python3',
        SENDER,
        '--mode',
        'all',
        'send',
        'cfe_es_noop_valid_shape',
        '--host',
        CI_HOST,
        '--port',
        CI_PORT,
        '--json'
      ]
    )
  rescue Exception => error
    marker_error = "#{error.class}: #{error.message}"
  end

  sleep(BASELINE_WAIT)
  {
    enabled: true,
    wait_sec: BASELINE_WAIT,
    marker_profile: 'cfe_es_noop_valid_shape',
    marker: marker_meta,
    error: marker_error
  }
end

def recovery_check
  control = establish_raw_ci_control
  { status: control[:ready] ? 'PASS' : 'FAIL', raw_ci_control: control }
end

def main
  ensure_allowed_mode!
  raise "Missing SP002 sender at #{SENDER}" unless File.exist?(SENDER)

  FileUtils.mkdir_p(REPORT_ROOT)
  packets_dir = File.join(REPORT_ROOT, 'packets')
  raw_ci_control = establish_raw_ci_control
  write_json(File.join(REPORT_ROOT, 'raw_ci_control_preflight.json'), raw_ci_control)
  raise 'SP002 could not restore a real raw-CI CFE_ES control/telemetry loop' unless raw_ci_control[:ready]

  selection_cmd = ['/usr/bin/python3', SENDER, '--mode', MODE]
  selection_cmd += ['--target', TARGET_FILTER] unless TARGET_FILTER.empty?
  TAG_FILTERS.each { |tag| selection_cmd += ['--tag', tag] }
  selection_cmd << 'build'
  selection_cmd.concat(PROFILE_IDS)
  selection_cmd << '--json'

  list, list_result = json_cmd(selection_cmd)
  profiles = list.is_a?(Array) ? list : [list]
  write_json(File.join(REPORT_ROOT, 'attack_description.json'), ATTACK_DESCRIPTION)
  write_json(File.join(REPORT_ROOT, 'selected_profiles.json'), profiles)
  write_json(File.join(REPORT_ROOT, 'profile_selection_command.json'), list_result)

  scores = []
  profiles.each_with_index do |profile, index|
    puts "#{SCENARIO_ID}: #{index + 1}/#{profiles.length} #{profile['profile_id']}"

    baseline_marker = prime_event_baseline
    before = snapshot(profile)
    send_meta, send_result = json_cmd(
      [
        '/usr/bin/python3',
        SENDER,
        '--mode',
        'all',
        'send',
        profile['profile_id'],
        '--host',
        CI_HOST,
        '--port',
        CI_PORT,
        '--dump-dir',
        packets_dir,
        '--json'
      ]
    )
    send_meta = send_meta[0] if send_meta.is_a?(Array)
    after_samples = collect_after_snapshots(profile)

    score = score_profile(profile, before, after_samples, send_meta, send_result)
    score[:baseline_marker] = baseline_marker
    scores << score
    write_profile_score(REPORT_ROOT, score)
  rescue Exception => error
    score = {
      scenario: SCENARIO_ID,
      profile_id: profile && profile['profile_id'],
      title: profile && profile['title'],
      target: profile && profile['target'],
      status: 'ERROR',
      attack_success: false,
      error_class: error.class.to_s,
      error: error.message
    }
    scores << score
    write_profile_score(REPORT_ROOT, score)
  end

  recovery = recovery_check
  pass_count = scores.count { |score| score[:status] == 'PASS' }
  fail_count = scores.count { |score| score[:status] == 'FAIL' }
  error_count = scores.count { |score| score[:status] == 'ERROR' }
  defended_count = scores.count { |score| score[:verdict] == 'defended' }
  inconclusive_count = scores.count { |score| score[:verdict] == 'inconclusive_no_cfs_observation' }
  sender_error_count = scores.count { |score| score[:verdict] == 'sender_error' }
  verdict_counts = scores.each_with_object(Hash.new(0)) { |score, counts| counts[score[:verdict] || 'error'] += 1 }
  total = scores.length

  summary = {
    scenario: SCENARIO_ID,
    name: SCENARIO_NAME,
    mode: MODE,
    ci_host: CI_HOST,
    ci_port: CI_PORT.to_i,
    report_dir: REPORT_ROOT,
    attack_description: ATTACK_DESCRIPTION,
    raw_ci_control_preflight: raw_ci_control,
    total: total,
    pass_count: pass_count,
    fail_count: fail_count,
    error_count: error_count,
    defended_count: defended_count,
    inconclusive_count: inconclusive_count,
    sender_error_count: sender_error_count,
    verdict_counts: verdict_counts,
    pass_rate: total.zero? ? 0.0 : pass_count.to_f / total,
    status: (pass_count.positive? && error_count.zero? && recovery[:status] == 'PASS') ? 'PASS' : 'FAIL',
    recovery: recovery,
    generated_at: Time.now.utc.iso8601
  }

  write_summary(REPORT_ROOT, summary, scores)

  puts "#{SCENARIO_ID} #{SCENARIO_NAME}: #{summary[:status]}"
  puts "Profiles: #{pass_count}/#{total} PASS (#{format('%.2f', summary[:pass_rate] * 100)}%)"
  puts "Errors: #{error_count}"
  puts "Defended: #{defended_count}"
  puts "Inconclusive: #{inconclusive_count}"
  puts "Recovery: #{recovery[:status]}"
  puts "Report: #{REPORT_ROOT}"

  scores.each do |score|
    verdict = score[:verdict] || 'error'
    stage = score[:defense_stage] ? " / #{score[:defense_stage]}" : ''
    puts "#{score[:profile_id]}: #{score[:status]} (#{verdict}#{stage})"
  end

  exit(summary[:status] == 'PASS' ? 0 : 1)
end

main
