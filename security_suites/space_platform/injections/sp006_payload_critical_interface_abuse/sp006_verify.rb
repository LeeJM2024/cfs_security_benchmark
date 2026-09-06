require 'json'
require 'fileutils'
require 'socket'
require 'time'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

SCENARIO_ID = 'SP006'
SCENARIO_NAME = 'Payload critical interface abuse'
REPORT_ROOT = ENV.fetch('SP006_REPORT_DIR', "/tmp/sp006_payload_abuse_results/#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}")
CI_HOST = ENV.fetch('SP006_CI_HOST', 'sc01-nos-fsw')
CI_PORT = ENV.fetch('SP006_CI_PORT', '5012').to_i
SELECTED_PROFILE_IDS = ENV.fetch('SP006_ONLY', '').split(',').map(&:strip).reject(&:empty?)

SP006_CMD_MID = 0x19F6
SP006_REQ_HK_MID = 0x19F7
SP006_HK_MID = 0x09F6
SP006_RUN_PROFILE_CC = 2

TO_LAB_CMD_MID = 0x18E8
EVS_EVENT_MID = 0x0808
CAM_CMD_MID = 0x18C8
CAM_SEND_HK_MID = 0x18C9
CAM_HK_MID = 0x08C8
CAM_EXP_MID = 0x08C9
GENERIC_RW_CMD_MID = 0x1992
GENERIC_RW_SEND_HK_MID = 0x1993
GENERIC_RW_HK_MID = 0x0993
GENERIC_THRUSTER_CMD_MID = 0x18EA
GENERIC_THRUSTER_REQ_HK_MID = 0x18EB
GENERIC_THRUSTER_HK_MID = 0x08EA

CAM_RESET_CC = 1
CAM_STOP_CC = 2
CAM_PAUSE_CC = 3
CAM_TIMEOUT_CC = 5
CAM_LOW_VOLTAGE_CC = 6
GENERIC_RW_RESET_CC = 1
GENERIC_RW_DISABLE_CC = 5
GENERIC_THRUSTER_RESET_CC = 1
GENERIC_THRUSTER_DISABLE_CC = 3

PROFILES = [
  {
    id: 2,
    name: 'CAM_COLLECTION_INTERRUPT',
    title: 'CAM collection interrupted by injected state command',
    expected: 'attack_success_if_running_collection_accepts_illegal_state_transition',
    args: { arg1: CAM_LOW_VOLTAGE_CC, delay_ms: 100 }
  },
  {
    id: 10,
    name: 'RW_DISABLED_SET_TORQUE',
    title: 'Reaction wheel set torque while disabled',
    expected: 'attack_success_if_disabled_actuator_accepts_output_command',
    args: { arg1: 0, arg2: 2500 }
  },
  {
    id: 20,
    name: 'THRUSTER_DISABLED_PERCENTAGE',
    title: 'Thruster percentage command while disabled',
    expected: 'fail_protected_if_thruster_rejects_disabled_output',
    args: { arg1: 0, arg2: 75 }
  },
  {
    id: 1,
    name: 'CAM_HWLIB_OUT_OF_ORDER',
    title: 'CAM low-level capture/read out of order',
    expected: 'attack_success_if_target_exposes_low_level_sequence_without_guard'
  }
].freeze

class SkipProfile < StandardError
  attr_reader :reason

  def initialize(reason)
    @reason = reason
    super(reason)
  end
end

def json_safe(value)
  case value
  when Hash
    value.each_with_object({}) { |(k, v), out| out[k] = json_safe(v) }
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

def write_profile_score(report_dir, score)
  profile_dir = File.join(report_dir, 'profiles', score[:profile_name].to_s)
  FileUtils.mkdir_p(profile_dir)
  write_json(File.join(profile_dir, 'score.json'), score)
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

def raw_to_lab_add(stream_mid, buffer_limit = 32)
  payload = [stream_mid & 0xFFFFFFFF].pack('V') + [0, 0, buffer_limit & 0xFF, 0].pack('C C C C')
  send_udp(command_packet(TO_LAB_CMD_MID, 6, payload))
end

def ensure_routes
  mids = {
    evs_event: EVS_EVENT_MID,
    sp006_hk: SP006_HK_MID,
    cam_hk: CAM_HK_MID,
    cam_exp: CAM_EXP_MID,
    rw_hk: GENERIC_RW_HK_MID,
    thruster_hk: GENERIC_THRUSTER_HK_MID
  }
  mids.each_with_object({}) do |(name, mid), routes|
    routes[name] = raw_to_lab_add(mid, 32)
    sleep(0.15)
  end
end

def telemetry_packet_exists?(target, packet)
  Cosmos::System.telemetry.packet(target, packet)
  true
rescue Exception
  false
end

def tlm_optional(target, packet, item)
  value = tlm("#{target} #{packet} #{item}")
  { ok: true, target: target, packet: packet, item: item, value: value, numeric: numeric(value) }
rescue Exception => error
  { ok: false, target: target, packet: packet, item: item, error_class: error.class.to_s, error: error.message }
end

def tlm_i(target, packet, item)
  numeric(tlm("#{target} #{packet} #{item}")).to_i
end

def numeric(value)
  return value.to_f if value.is_a?(Numeric)

  value.to_s.strip.to_f
end

def clean_string(value)
  value.to_s.delete("\u0000").strip
end

def read_event_packet
  {
    sequence: tlm_i('CFS', 'CFE_EVS_PACKET', 'CCSDS_SEQUENCE'),
    app_name: clean_string(tlm('CFS CFE_EVS_PACKET PACKETID_APPNAME')),
    event_id: tlm_i('CFS', 'CFE_EVS_PACKET', 'PACKETID_EVENTID'),
    event_type: tlm_i('CFS', 'CFE_EVS_PACKET', 'PACKETID_EVENTTYPE'),
    message: clean_string(tlm('CFS CFE_EVS_PACKET MESSAGE')),
    observed_at: Time.now.utc.iso8601
  }
end

def collect_events(duration_seconds = 6.0, interval = 0.15)
  deadline = Time.now + duration_seconds
  events = []
  errors = []
  last_seq = nil

  until Time.now >= deadline
    begin
      event = read_event_packet
      if !event[:sequence].nil? && event[:sequence] != last_seq
        events << event
        last_seq = event[:sequence]
      end
    rescue Exception => error
      errors << { error_class: error.class.to_s, error: error.message } if errors.length < 5
    end
    sleep(interval)
  end

  { events: events, errors: errors }
end

def event_messages(events, app: nil)
  Array(events[:events]).select { |event| app.nil? || event[:app_name] == app }.map { |event| event[:message].to_s }
end

def message_seen?(events, pattern, app: nil)
  event_messages(events, app: app).any? { |message| message.match?(pattern) }
end

def request_sp006_hk
  send_udp(command_packet(SP006_REQ_HK_MID, 0, ''.b))
end

def request_cam_hk
  send_udp(command_packet(CAM_SEND_HK_MID, 0, ''.b))
end

def request_rw_hk
  send_udp(command_packet(GENERIC_RW_SEND_HK_MID, 0, ''.b))
end

def request_thruster_hk
  send_udp(command_packet(GENERIC_THRUSTER_REQ_HK_MID, 0, ''.b))
end

def read_sp006_hk(refresh: true)
  return { available: false, reason: 'SP006 telemetry dictionary is not loaded' } unless telemetry_packet_exists?('CFS', 'SP006_HK_TLM')

  if refresh
    request_sp006_hk
    sleep(0.25)
  end

  {
    available: true,
    cmd_count: tlm_i('CFS', 'SP006_HK_TLM', 'COMMANDCOUNT'),
    err_count: tlm_i('CFS', 'SP006_HK_TLM', 'COMMANDERRCOUNT'),
    last_profile_id: tlm_i('CFS', 'SP006_HK_TLM', 'LASTPROFILEID'),
    last_target_id: tlm_i('CFS', 'SP006_HK_TLM', 'LASTTARGETID'),
    last_target_mid: tlm_i('CFS', 'SP006_HK_TLM', 'LASTTARGETMSGID'),
    last_target_fc: tlm_i('CFS', 'SP006_HK_TLM', 'LASTTARGETFCNCODE'),
    last_repeat_count: tlm_i('CFS', 'SP006_HK_TLM', 'LASTREPEATCOUNT'),
    last_status: tlm_i('CFS', 'SP006_HK_TLM', 'LASTSTATUS'),
    profiles_executed: tlm_i('CFS', 'SP006_HK_TLM', 'PROFILESEXECUTED'),
    target_command_count: tlm_i('CFS', 'SP006_HK_TLM', 'TARGETCOMMANDCOUNT'),
    target_command_error_count: tlm_i('CFS', 'SP006_HK_TLM', 'TARGETCOMMANDERRORCOUNT'),
    multi_command_count: tlm_i('CFS', 'SP006_HK_TLM', 'MULTICOMMANDCOUNT')
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def read_cam_hk(refresh: true)
  return { available: false, reason: 'ARDUCAM HK telemetry dictionary is not loaded' } unless telemetry_packet_exists?('ARDUCAM', 'ARDUCAM_HK_TLM_T')

  if refresh
    request_cam_hk
    sleep(0.25)
  end

  {
    available: true,
    sequence: tlm_i('ARDUCAM', 'ARDUCAM_HK_TLM_T', 'CCSDS_SEQUENCE'),
    cmd_count: tlm_i('ARDUCAM', 'ARDUCAM_HK_TLM_T', 'COMMANDCOUNT'),
    err_count: tlm_i('ARDUCAM', 'ARDUCAM_HK_TLM_T', 'COMMANDERRORCOUNT')
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def read_cam_exp(refresh: false)
  return { available: false, reason: 'ARDUCAM EXP telemetry dictionary is not loaded' } unless telemetry_packet_exists?('ARDUCAM', 'ARDUCAM_EXP_TLM_T')

  {
    available: true,
    sequence: tlm_i('ARDUCAM', 'ARDUCAM_EXP_TLM_T', 'CCSDS_SEQUENCE'),
    msg_count: tlm_i('ARDUCAM', 'ARDUCAM_EXP_TLM_T', 'MSG_COUNT'),
    length: tlm_i('ARDUCAM', 'ARDUCAM_EXP_TLM_T', 'CAM_FIFO_LENGTH')
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def read_rw_hk(refresh: true)
  return { available: false, reason: 'SP006 RW HK telemetry dictionary is not loaded' } unless telemetry_packet_exists?('CFS', 'SP006_RW_HK_TLM')

  if refresh
    request_rw_hk
    sleep(0.25)
  end

  {
    available: true,
    sequence: tlm_i('CFS', 'SP006_RW_HK_TLM', 'CCSDS_SEQUENCE'),
    cmd_count: tlm_i('CFS', 'SP006_RW_HK_TLM', 'COMMANDCOUNTER'),
    err_count: tlm_i('CFS', 'SP006_RW_HK_TLM', 'COMMANDERRCOUNTER'),
    device_count_rw0: tlm_i('CFS', 'SP006_RW_HK_TLM', 'DEVICECOUNT_RW0'),
    device_error_rw0: tlm_i('CFS', 'SP006_RW_HK_TLM', 'DEVICEERRORCOUNT_RW0'),
    enabled_rw0: tlm_i('CFS', 'SP006_RW_HK_TLM', 'DEVICEENABLED_RW0')
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def read_thruster_hk(refresh: true)
  return { available: false, reason: 'SP006 thruster HK telemetry dictionary is not loaded' } unless telemetry_packet_exists?('CFS', 'SP006_THRUSTER_HK_TLM')

  if refresh
    request_thruster_hk
    sleep(0.25)
  end

  {
    available: true,
    sequence: tlm_i('CFS', 'SP006_THRUSTER_HK_TLM', 'CCSDS_SEQUENCE'),
    cmd_count: tlm_i('CFS', 'SP006_THRUSTER_HK_TLM', 'COMMANDCOUNT'),
    err_count: tlm_i('CFS', 'SP006_THRUSTER_HK_TLM', 'COMMANDERRCOUNT'),
    device_count: tlm_i('CFS', 'SP006_THRUSTER_HK_TLM', 'DEVICECOUNT'),
    device_error_count: tlm_i('CFS', 'SP006_THRUSTER_HK_TLM', 'DEVICEERRORCOUNT'),
    enabled: tlm_i('CFS', 'SP006_THRUSTER_HK_TLM', 'DEVICEENABLED')
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end

def sp006_run_profile(profile, opts = {})
  args = profile.fetch(:args, {}).merge(opts)
  payload = [
    profile[:id].to_i,
    args.fetch(:flags, 0).to_i,
    args.fetch(:repeat_count, 0).to_i,
    args.fetch(:delay_ms, 0).to_i
  ].pack('v v v v')
  payload << [
    args.fetch(:arg1, 0).to_i,
    args.fetch(:arg2, 0).to_i,
    args.fetch(:arg3, 0).to_i,
    args.fetch(:arg4, 0).to_i
  ].pack('l< l< l< l<')

  send_udp(command_packet(SP006_CMD_MID, SP006_RUN_PROFILE_CC, payload)).merge(profile_id: profile[:id], profile_name: profile[:name], args: args)
end

def raw_cam_command(fc)
  send_udp(command_packet(CAM_CMD_MID, fc, ''.b)).merge(mid: CAM_CMD_MID, fc: fc)
end

def raw_rw_command(fc, wheel = 0, data = 0)
  payload = [wheel.to_i & 0xFF, data.to_i].pack('C s<')
  send_udp(command_packet(GENERIC_RW_CMD_MID, fc, payload)).merge(mid: GENERIC_RW_CMD_MID, fc: fc, wheel: wheel, data: data)
end

def raw_rw_noargs(fc)
  send_udp(command_packet(GENERIC_RW_CMD_MID, fc, ''.b)).merge(mid: GENERIC_RW_CMD_MID, fc: fc)
end

def raw_thruster_command(fc)
  send_udp(command_packet(GENERIC_THRUSTER_CMD_MID, fc, ''.b)).merge(mid: GENERIC_THRUSTER_CMD_MID, fc: fc)
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


def telemetry_live?(packet)
  packet[:available] && packet[:sequence].to_i.positive?
end

def wait_cam_hk_sequence_after(before_sequence, timeout = 4.0)
  wait_until(timeout, 0.4) do
    current = read_cam_hk(refresh: true)
    matched = current[:available] && current[:sequence].to_i > before_sequence.to_i
    { matched: matched, before_sequence: before_sequence, current: current }
  end
end

def wait_sp006_profile(profile_id, before_hk, timeout = 6.0)
  before_count = before_hk[:available] ? before_hk[:cmd_count].to_i : nil
  wait_until(timeout, 0.4) do
    current = read_sp006_hk(refresh: true)
    matched = current[:available] && current[:last_profile_id].to_i == profile_id.to_i &&
              (!before_count || current[:cmd_count].to_i > before_count)
    { matched: matched, before: before_hk, current: current }
  end
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
  raise SkipProfile, "Unknown SP006 profile(s): #{missing.join(', ')}" unless missing.empty?
  selected
end

def score(verdict:, attack_success:, classification:, safety_meaning:, evidence:, profile:, notes: [])
  {
    scenario: SCENARIO_ID,
    profile_id: profile[:id],
    profile_name: profile[:name],
    title: profile[:title],
    expected: profile[:expected],
    verdict: verdict,
    attack_success: attack_success,
    classification: classification,
    safety_meaning: safety_meaning,
    evidence: evidence,
    notes: notes,
    completed_at: Time.now.utc.iso8601
  }
end

def verify_cam_out_of_order(profile)
  raw_cam_command(CAM_RESET_CC)
  sleep(0.3)
  before_sp006 = read_sp006_hk
  before_cam = read_cam_hk
  before_exp = read_cam_exp

  unless telemetry_live?(before_cam)
    return score(
      verdict: 'SKIP',
      attack_success: false,
      classification: 'SKIP_TARGET_APP_NOT_RUNNING',
      safety_meaning: 'CAM/arducam housekeeping did not become live, so the target component is not running or not routed in this NOS3 configuration; security effect cannot be tested.',
      evidence: { before_cam_hk: before_cam, before_cam_exp: before_exp, before_sp006_hk: before_sp006 },
      profile: profile
    )
  end

  trigger = sp006_run_profile(profile)
  events = collect_events(5.0, 0.15)
  sp006_wait = wait_sp006_profile(profile[:id], before_sp006, 2.0)
  after_cam = read_cam_hk
  after_exp = read_cam_exp
  cam_liveness_after = after_cam[:available] ? wait_cam_hk_sequence_after(after_cam[:sequence], 4.0) : nil

  exp_changed = before_exp[:available] && after_exp[:available] && after_exp[:sequence].to_i != before_exp[:sequence].to_i
  cam_error = after_cam[:available] && before_cam[:available] && after_cam[:err_count].to_i > before_cam[:err_count].to_i
  sp006_sent = sp006_wait[:matched] && sp006_wait.dig(:current, :last_status).to_i == 0 &&
               sp006_wait.dig(:current, :last_target_fc).to_i == 31
  cam_stalled = sp006_sent && after_cam[:available] && cam_liveness_after && !cam_liveness_after[:matched]

  evidence = {
    trigger: trigger,
    sp006_wait: sp006_wait,
    before_cam_hk: before_cam,
    after_cam_hk: after_cam,
    cam_liveness_after: cam_liveness_after,
    before_cam_exp: before_exp,
    after_cam_exp: after_exp,
    events: events
  }

  if exp_changed
    score(
      verdict: 'PASS',
      attack_success: true,
      classification: 'ATTACK_SUCCESS_SEQUENCE_GUARD_MISSING',
      safety_meaning: 'CAM accepted an out-of-order low-level capture/read sequence far below the normal experiment flow and produced experiment telemetry.',
      evidence: evidence,
      profile: profile
    )
  elsif sp006_sent && cam_stalled
    score(
      verdict: 'PASS',
      attack_success: true,
      classification: 'ATTACK_SUCCESS_CAM_APP_OR_PIPE_STALLED',
      safety_meaning: 'CAM was live before the legal-format low-level debug sequence, but stopped advancing housekeeping afterward; the attack produced a target-side availability/control-flow impact instead of a clean rejection.',
      evidence: evidence,
      profile: profile
    )
  elsif sp006_sent && cam_error
    score(
      verdict: 'FAIL',
      attack_success: false,
      classification: 'FAIL_TARGET_REJECTED_OR_ERRORED',
      safety_meaning: 'CAM did not produce experiment telemetry from the out-of-order low-level sequence; CAM error telemetry changed.',
      evidence: evidence,
      profile: profile
    )
  elsif sp006_sent
    score(
      verdict: 'FAIL',
      attack_success: false,
      classification: 'OBSERVATION_LIMIT_NO_TARGET_EFFECT',
      safety_meaning: 'SP006 transmitted the out-of-order CAM low-level commands, but the available target telemetry/events did not prove execution or rejection.',
      evidence: evidence,
      profile: profile,
      notes: ['CAM HWLIB_CAPTURE/HWLIB_READ handlers do not emit EVS or increment CAM HK command count; CAM_EXP telemetry is the strongest in-band effect.']
    )
  else
    score(
      verdict: 'FAIL',
      attack_success: false,
      classification: 'FAIL_TRIGGER_OR_SP006_NOT_OBSERVED',
      safety_meaning: 'The malicious trigger app did not report a successful profile transmission.',
      evidence: evidence,
      profile: profile
    )
  end
end

def verify_cam_interrupt(profile)
  raw_cam_command(CAM_STOP_CC)
  raw_cam_command(CAM_RESET_CC)
  sleep(0.5)
  before_sp006 = read_sp006_hk
  before_cam = read_cam_hk

  unless telemetry_live?(before_cam)
    return score(
      verdict: 'SKIP',
      attack_success: false,
      classification: 'SKIP_TARGET_APP_NOT_RUNNING',
      safety_meaning: 'CAM/arducam housekeeping did not become live, so the target component is not running or not routed in this NOS3 configuration; security effect cannot be tested.',
      evidence: { before_cam_hk: before_cam, before_sp006_hk: before_sp006 },
      profile: profile
    )
  end

  trigger = sp006_run_profile(profile)
  events = collect_events(8.0, 0.15)
  sp006_wait = wait_sp006_profile(profile[:id], before_sp006, 2.0)
  after_cam = read_cam_hk

  exp_seen = message_seen?(events, /EXP 3 Command - Large Picture/, app: 'CAM')
  interrupt_seen = message_seen?(events, /LOW_VOLTAGE command|TIMEOUT command|STOP command|PAUSE command/, app: 'CAM')
  cam_count_delta = after_cam[:available] && before_cam[:available] ? after_cam[:cmd_count].to_i - before_cam[:cmd_count].to_i : nil
  sp006_sent = sp006_wait[:matched] && sp006_wait.dig(:current, :last_status).to_i == 0

  evidence = {
    trigger: trigger,
    sp006_wait: sp006_wait,
    before_cam_hk: before_cam,
    after_cam_hk: after_cam,
    cam_command_count_delta: cam_count_delta,
    events: events
  }

  if sp006_sent && exp_seen && interrupt_seen && (!cam_count_delta.nil? && cam_count_delta >= 2)
    score(
      verdict: 'PASS',
      attack_success: true,
      classification: 'ATTACK_SUCCESS_ILLEGAL_STATE_TRANSITION_ACCEPTED',
      safety_meaning: 'CAM accepted a collection command and then accepted an injected interrupt/state command while the operation window was active.',
      evidence: evidence,
      profile: profile
    )
  elsif sp006_sent && (exp_seen || interrupt_seen || (!cam_count_delta.nil? && cam_count_delta > 0))
    score(
      verdict: 'FAIL',
      attack_success: false,
      classification: 'OBSERVATION_LIMIT_PARTIAL_TARGET_EVIDENCE',
      safety_meaning: 'CAM showed partial target-side evidence, but not enough to prove both collection start and injected state transition.',
      evidence: evidence,
      profile: profile
    )
  else
    score(
      verdict: 'FAIL',
      attack_success: false,
      classification: sp006_sent ? 'FAIL_TARGET_DID_NOT_SHOW_EFFECT' : 'FAIL_TRIGGER_OR_SP006_NOT_OBSERVED',
      safety_meaning: 'The verifier did not observe CAM accepting the collection/interruption sequence.',
      evidence: evidence,
      profile: profile
    )
  end
end

def ensure_rw0_disabled
  before = read_rw_hk
  reset = raw_rw_noargs(GENERIC_RW_RESET_CC)
  sleep(0.25)
  disable = raw_rw_command(GENERIC_RW_DISABLE_CC, 0, 0)
  wait = wait_until(5.0, 0.4) do
    current = read_rw_hk(refresh: true)
    matched = current[:available] && current[:enabled_rw0].to_i == 0
    { matched: matched, current: current }
  end
  after = wait[:current] || read_rw_hk
  { before: before, reset: reset, disable: disable, wait: wait, after: after, ok: after[:available] && after[:enabled_rw0].to_i == 0 }
end

def verify_rw_disabled_set_torque(profile)
  precondition = ensure_rw0_disabled
  raise SkipProfile, "RW0 could not be confirmed disabled before attack" unless precondition[:ok]

  before_sp006 = read_sp006_hk
  before_rw = read_rw_hk
  trigger = sp006_run_profile(profile)
  events = collect_events(4.0, 0.15)
  sp006_wait = wait_sp006_profile(profile[:id], before_sp006, 2.0)
  after_rw = read_rw_hk

  set_torque_seen = message_seen?(events, /Set Torque Command received/i, app: 'GENERIC_RW')
  uart_write_error_seen = message_seen?(events, /Error writing to UART/i, app: 'GENERIC_RW')
  rw_cmd_delta = after_rw[:available] && before_rw[:available] ? after_rw[:cmd_count].to_i - before_rw[:cmd_count].to_i : nil
  rw_dev_delta = after_rw[:available] && before_rw[:available] ? after_rw[:device_count_rw0].to_i - before_rw[:device_count_rw0].to_i : nil
  rw_err_delta = after_rw[:available] && before_rw[:available] ? after_rw[:device_error_rw0].to_i - before_rw[:device_error_rw0].to_i : nil
  still_disabled = after_rw[:available] && after_rw[:enabled_rw0].to_i == 0
  sp006_sent = sp006_wait[:matched] && sp006_wait.dig(:current, :last_status).to_i == 0

  evidence = {
    precondition: precondition,
    trigger: trigger,
    sp006_wait: sp006_wait,
    before_rw_hk: before_rw,
    after_rw_hk: after_rw,
    rw_command_count_delta: rw_cmd_delta,
    rw_device_count_delta: rw_dev_delta,
    rw_device_error_delta: rw_err_delta,
    events: events
  }

  if sp006_sent && still_disabled && (set_torque_seen || uart_write_error_seen || (!rw_dev_delta.nil? && rw_dev_delta > 0) || (!rw_err_delta.nil? && rw_err_delta > 0))
    score(
      verdict: 'PASS',
      attack_success: true,
      classification: 'ATTACK_SUCCESS_DISABLED_ACTUATOR_OUTPUT_PATH_REACHED',
      safety_meaning: 'Reaction wheel was confirmed disabled, yet the target accepted SET_TORQUE far enough to enter the actuator write path instead of rejecting on enabled/armed state.',
      evidence: evidence,
      profile: profile,
      notes: ['If the UART write failed, this still proves missing explicit state guard but does not prove physical torque output.']
    )
  elsif sp006_sent && still_disabled && !rw_cmd_delta.nil? && rw_cmd_delta <= 0
    score(
      verdict: 'FAIL',
      attack_success: false,
      classification: 'FAIL_PROTECTED_OR_DEVICE_WRITE_NOT_REACHED',
      safety_meaning: 'RW stayed disabled and no target-side set-torque acceptance/write evidence was observed.',
      evidence: evidence,
      profile: profile
    )
  else
    score(
      verdict: 'FAIL',
      attack_success: false,
      classification: sp006_sent ? 'OBSERVATION_LIMIT_RW_EFFECT_NOT_PROVEN' : 'FAIL_TRIGGER_OR_SP006_NOT_OBSERVED',
      safety_meaning: 'The verifier could not prove a disabled-state RW output path was reached.',
      evidence: evidence,
      profile: profile
    )
  end
end

def ensure_thruster_disabled
  before = read_thruster_hk
  reset = raw_thruster_command(GENERIC_THRUSTER_RESET_CC)
  sleep(0.25)
  disable = raw_thruster_command(GENERIC_THRUSTER_DISABLE_CC)
  sleep(0.8)
  after = read_thruster_hk
  { before: before, reset: reset, disable: disable, after: after, ok: after[:available] && after[:enabled].to_i == 0 }
end

def verify_thruster_disabled_percentage(profile)
  precondition = ensure_thruster_disabled
  raise SkipProfile, "Thruster could not be confirmed disabled before attack" unless precondition[:ok]

  before_sp006 = read_sp006_hk
  before_thruster = read_thruster_hk
  trigger = sp006_run_profile(profile)
  events = collect_events(4.0, 0.15)
  sp006_wait = wait_sp006_profile(profile[:id], before_sp006, 2.0)
  after_thruster = read_thruster_hk

  rejected_seen = message_seen?(events, /Cannot turn thruster on, they are disabled/i, app: 'THRUSTER')
  accepted_seen = message_seen?(events, /percentage on/i, app: 'THRUSTER')
  err_delta = after_thruster[:available] && before_thruster[:available] ? after_thruster[:err_count].to_i - before_thruster[:err_count].to_i : nil
  cmd_delta = after_thruster[:available] && before_thruster[:available] ? after_thruster[:cmd_count].to_i - before_thruster[:cmd_count].to_i : nil
  still_disabled = after_thruster[:available] && after_thruster[:enabled].to_i == 0
  sp006_sent = sp006_wait[:matched] && sp006_wait.dig(:current, :last_status).to_i == 0

  evidence = {
    precondition: precondition,
    trigger: trigger,
    sp006_wait: sp006_wait,
    before_thruster_hk: before_thruster,
    after_thruster_hk: after_thruster,
    thruster_command_count_delta: cmd_delta,
    thruster_error_count_delta: err_delta,
    events: events
  }

  if sp006_sent && still_disabled && (rejected_seen || (!err_delta.nil? && err_delta > 0)) && !accepted_seen
    score(
      verdict: 'FAIL',
      attack_success: false,
      classification: 'FAIL_PROTECTED_STATE_CHECK_ENFORCED',
      safety_meaning: 'Thruster rejected the percentage/output command while disabled; this is a target-side state guard working as intended.',
      evidence: evidence,
      profile: profile
    )
  elsif sp006_sent && accepted_seen
    score(
      verdict: 'PASS',
      attack_success: true,
      classification: 'ATTACK_SUCCESS_DISABLED_THRUSTER_OUTPUT_ACCEPTED',
      safety_meaning: 'Thruster accepted a percentage/output command while disabled.',
      evidence: evidence,
      profile: profile
    )
  else
    score(
      verdict: 'FAIL',
      attack_success: false,
      classification: sp006_sent ? 'OBSERVATION_LIMIT_THRUSTER_EFFECT_NOT_PROVEN' : 'FAIL_TRIGGER_OR_SP006_NOT_OBSERVED',
      safety_meaning: 'The verifier could not prove whether the disabled-state thruster command was accepted or rejected.',
      evidence: evidence,
      profile: profile
    )
  end
end

def verify_profile(profile)
  case profile[:name]
  when 'CAM_HWLIB_OUT_OF_ORDER'
    verify_cam_out_of_order(profile)
  when 'CAM_COLLECTION_INTERRUPT'
    verify_cam_interrupt(profile)
  when 'RW_DISABLED_SET_TORQUE'
    verify_rw_disabled_set_torque(profile)
  when 'THRUSTER_DISABLED_PERCENTAGE'
    verify_thruster_disabled_percentage(profile)
  else
    raise SkipProfile, "No verifier implementation for #{profile[:name]}"
  end
rescue SkipProfile => error
  score(
    verdict: 'SKIP',
    attack_success: false,
    classification: 'SKIP_PRECONDITION_NOT_MET',
    safety_meaning: error.reason,
    evidence: { error: error.reason },
    profile: profile
  )
rescue Exception => error
  score(
    verdict: 'FAIL',
    attack_success: false,
    classification: 'FAIL_VERIFIER_ERROR',
    safety_meaning: 'Verifier error prevented a security-relevant conclusion.',
    evidence: { error_class: error.class.to_s, error: error.message, backtrace: error.backtrace&.first(8) },
    profile: profile
  )
end

def summarize(scores)
  {
    scenario: SCENARIO_ID,
    name: SCENARIO_NAME,
    generated_at: Time.now.utc.iso8601,
    report_root: REPORT_ROOT,
    total: scores.length,
    pass_attack_success: scores.count { |score| score[:verdict] == 'PASS' && score[:attack_success] },
    fail_protected: scores.count { |score| score[:classification].to_s.start_with?('FAIL_PROTECTED') },
    observation_limits: scores.count { |score| score[:classification].to_s.start_with?('OBSERVATION_LIMIT') },
    skips: scores.count { |score| score[:verdict] == 'SKIP' },
    failures: scores.count { |score| score[:verdict] == 'FAIL' && !score[:classification].to_s.start_with?('FAIL_PROTECTED') && !score[:classification].to_s.start_with?('OBSERVATION_LIMIT') },
    scores: scores.map do |score|
      {
        profile_id: score[:profile_id],
        profile_name: score[:profile_name],
        verdict: score[:verdict],
        attack_success: score[:attack_success],
        classification: score[:classification],
        safety_meaning: score[:safety_meaning]
      }
    end
  }
end

FileUtils.mkdir_p(REPORT_ROOT)
start = Time.now.utc
selected = select_profiles
routes = ensure_routes
sleep(1.0)
initial_hk = {
  sp006: read_sp006_hk,
  cam: read_cam_hk,
  cam_exp: read_cam_exp,
  rw: read_rw_hk,
  thruster: read_thruster_hk
}

scores = selected.map do |profile|
  result = verify_profile(profile)
  write_profile_score(REPORT_ROOT, result)
  puts "#{result[:profile_name]}: #{result[:verdict]} #{result[:classification]}"
  result
end

summary = summarize(scores).merge(started_at: start.iso8601, routes: routes, initial_hk: initial_hk)
write_json(File.join(REPORT_ROOT, 'summary.json'), summary)
puts JSON.pretty_generate(summary)

exit(summary[:failures].positive? ? 1 : 0)
