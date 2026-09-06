require 'json'
require 'fileutils'
require 'time'
require 'digest'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

SCENARIO_ID = 'SP003'
SCENARIO_NAME = 'cFS app crash and restart pressure'
MODE = ENV.fetch('SP003_MODE', 'safe').downcase
REPORT_ROOT = ENV.fetch('SP003_REPORT_DIR', "/tmp/sp003_app_crash_restart_results/#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}")
APP_NAME = 'SP003'
APP_ENTRY = 'SP003_AppMain'
APP_FILE = '/cf/sp003_crash.so'
HOST_CF_DIR = ENV.fetch('SP003_HOST_CF_DIR', '/home/leejm/nos3/fsw/build/exe/cpu1/cf')
SYSLOG_DUMP_CFE_PATH = '/cf/s3sys.log'
SYSLOG_DUMP_HOST_PATH = File.join(HOST_CF_DIR, File.basename(SYSLOG_DUMP_CFE_PATH))
SP003_HK_MID = 0x09F2
FM_HK_MID = 0x088A
ES_HK_MID = 0x0800
EVS_HK_MID = 0x0801
EVS_EVENT_MID = 0x0808
FM_APP_NAME = 'FM'
FM_APP_ENTRY = 'FM_AppMain'
FM_APP_FILE = '/cf/fm.so'
FM_APP_STACK = 32768
FM_APP_PRIORITY = 52
FM_HOST_PATH = File.join(HOST_CF_DIR, File.basename(FM_APP_FILE))
FM_BACKUP_HOST_PATH = File.join(HOST_CF_DIR, 'sp003_backup_fm.so')
ES_ONE_APP_MID = 0x080B
SCH_CPU_ATTACK_MS = 8000
SCH_CPU_SAMPLE_INTERVAL = 1.0
SCH_CPU_BASELINE_SECONDS = 5
SCH_CPU_ATTACK_SECONDS = 10
SCH_CPU_RECOVERY_SECONDS = 5
SCH_CPU_RATE_RATIO_THRESHOLD = 0.70
EVS_EVENT_FLOOD_COUNT = 200
EVS_EVENT_FLOOD_DELAY_MS = 10
EVS_SENTINEL_CAPTURE_SECONDS = 3.0
EVS_ATTACK_CAPTURE_SECONDS = 6.0
EVS_SENTINEL_DELAY_RATIO_THRESHOLD = 3.0
EVS_SENTINEL_DELAY_SECONDS_THRESHOLD = 1.0
EVS_EVENT_FLOOD_EID_BASE = 100
EVS_EVENT_FLOOD_EID_COUNT = 128
ES_SYSLOG_FLOOD_COUNT = 200
ES_SYSLOG_ENTRY_DELTA_THRESHOLD = 20
ES_SYSLOG_BYTES_DELTA_THRESHOLD = 1024
SYSLOG_PRESSURE_DOMINANCE_THRESHOLD = 0.60

START_APP_CANDIDATES = [
  "CFE CFE_ES_START_APP with APPLICATION #{APP_NAME}, APPENTRYPOINT #{APP_ENTRY}, APPFILENAME #{APP_FILE}, STACKSIZE 32768, EXCEPTIONACTION 0, PRIORITY 89",
  "CFS CFE_ES_START_APP with APPLICATION #{APP_NAME}, APPENTRYPOINT #{APP_ENTRY}, APPFILENAME #{APP_FILE}, STACKSIZE 32768, EXCEPTIONACTION 0, PRIORITY 89"
]

RESTART_APP_CANDIDATES = [
  "CFE CFE_ES_RESTART_APP with APPLICATION #{APP_NAME}",
  "CFS CFE_ES_RESTART_APP with APPLICATION #{APP_NAME}"
]

STOP_APP_CANDIDATES = [
  "CFE CFE_ES_STOP_APP with APPLICATION #{APP_NAME}",
  "CFS CFE_ES_STOP_APP with APPLICATION #{APP_NAME}"
]

START_FM_CANDIDATES = [
  "CFE CFE_ES_START_APP with APPLICATION #{FM_APP_NAME}, APPENTRYPOINT #{FM_APP_ENTRY}, APPFILENAME #{FM_APP_FILE}, STACKSIZE #{FM_APP_STACK}, EXCEPTIONACTION 0, PRIORITY #{FM_APP_PRIORITY}",
  "CFS CFE_ES_START_APP with APPLICATION #{FM_APP_NAME}, APPENTRYPOINT #{FM_APP_ENTRY}, APPFILENAME #{FM_APP_FILE}, STACKSIZE #{FM_APP_STACK}, EXCEPTIONACTION 0, PRIORITY #{FM_APP_PRIORITY}"
]

ES_NOOP_CANDIDATES = [
  'CFE CFE_ES_NOOP',
  'CFS CFE_ES_NOOP'
]

ES_CLEAR_SYSLOG_CANDIDATES = [
  'CFE CFE_ES_CLEAR_SYSLOG',
  'CFS CFE_ES_CLEAR_SYSLOG'
]

ES_WRITE_SYSLOG_CANDIDATES = [
  "CFE CFE_ES_WRITE_SYSLOG with SYSLOGFILENAME #{SYSLOG_DUMP_CFE_PATH}",
  "CFS CFE_ES_WRITE_SYSLOG with SYSLOGFILENAME #{SYSLOG_DUMP_CFE_PATH}"
]

EVS_CLEAR_LOG_CANDIDATES = [
  'CFE CFE_EVS_CLEAR_LOG',
  'CFS CFE_EVS_CLEAR_LOG'
]

ATTACK_DESCRIPTION = {
  attack_entry: 'Benchmark-controlled cFS app executes runtime pressure actions from inside flight software',
  affected_components: 'cFE Executive Services, external cFS app lifecycle, ER log, syslog, scheduler/telemetry timing under bounded app pressure',
  cps_type: 'Runtime fault injection / app lifecycle abuse / restart pressure',
  security_consequence: 'A malicious or compromised app can exit, request restarts/deletes/reloads, consume CPU, flood events/syslog, or attempt crash loops that degrade observability and availability',
  recovery_strategy: 'Restart or reload benchmark-owned app, disarm persistent startup-fault state, verify ES and SP003 HK telemetry recover',
  nos3_cfs_injection: 'CFE_ES_START_APP loads /cf/sp003_crash.so; CFS SP003_RUN_PROFILE selects runtime pressure profile'
}

PROFILE_IDS = {
  clear_persistent_state: 50,
  self_exit_error: 2,
  self_restart_api: 3,
  restart_target_api: 10,
  delete_target_api: 11,
  reload_target_api: 12,
  busy_loop_ms: 20,
  event_burst: 21,
  syslog_burst: 22,
  syslog_sentinel: 23,
  arm_startup_fault_loop: 30,
  disarm_startup_fault: 31,
  segfault: 40,
  abort: 41
}

STARTUP_FAULT = {
  none: 0,
  exit_error: 1,
  segfault: 2,
  abort: 3,
  restart_self: 4
}

class SkipProfile < StandardError
  attr_reader :reason

  def initialize(reason)
    @reason = reason
    super(reason)
  end
end

def scalar_to_i(value)
  return value if value.is_a?(Integer)
  return value.to_i if value.is_a?(Float)

  text = value.to_s.strip
  text.to_i
end

def tlm_i(target, packet, item)
  scalar_to_i(tlm("#{target} #{packet} #{item}"))
end

def command_target_exists?(target)
  Cosmos::System.commands.target_names.include?(target)
rescue Exception
  false
end

def telemetry_packet_exists?(target, packet)
  Cosmos::System.telemetry.packet(target, packet)
  true
rescue Exception
  false
end

def require_command_target!(target)
  raise SkipProfile, "COSMOS/OpenC3 command target #{target} is not loaded" unless command_target_exists?(target)
end

def require_sp003_dictionary!
  require_command_target!('CFS')
  raise 'SP003 command dictionary is not loaded in COSMOS/OpenC3' unless command_available?('CFS', 'SP003_RUN_PROFILE')
  raise 'SP003 telemetry dictionary is not loaded in COSMOS/OpenC3' unless telemetry_packet_exists?('CFS', 'SP003_HK_TLM')
end

def command_available?(target, command)
  Cosmos::System.commands.packet(target, command)
  true
rescue Exception
  false
end

def cmd_first(candidates)
  errors = []
  candidates.each do |candidate|
    begin
      cmd(candidate)
      return { ok: true, command: candidate }
    rescue Exception => error
      errors << { command: candidate, error_class: error.class.to_s, error: error.message }
    end
  end
  { ok: false, errors: errors }
end

def cmd_optional(command)
  cmd(command)
  { ok: true, command: command }
rescue Exception => error
  { ok: false, command: command, error_class: error.class.to_s, error: error.message }
end

def wait_until(timeout_seconds = 8.0, interval = 0.5)
  deadline = Time.now + timeout_seconds
  last = yield

  until last[:matched] || Time.now >= deadline
    sleep(interval)
    last = yield
  end

  last
end

def write_json(path, object)
  FileUtils.mkdir_p(File.dirname(path))
  File.write(path, JSON.pretty_generate(object) + "\n")
end

def write_profile_score(report_dir, score)
  profile_dir = File.join(report_dir, 'profiles', score[:profile_id].to_s)
  FileUtils.mkdir_p(profile_dir)
  write_json(File.join(profile_dir, 'score.json'), score)
end

def read_es
  {
    cmd_count: tlm_i('CFS', 'CFE_ES_HKPACKET', 'CMDCOUNTER'),
    err_count: tlm_i('CFS', 'CFE_ES_HKPACKET', 'ERRCOUNTER'),
    syslog_bytes_used: tlm_i('CFS', 'CFE_ES_HKPACKET', 'SYSLOGBYTESUSED'),
    syslog_size: tlm_i('CFS', 'CFE_ES_HKPACKET', 'SYSLOGSIZE'),
    syslog_entries: tlm_i('CFS', 'CFE_ES_HKPACKET', 'SYSLOGENTRIES'),
    syslog_mode: tlm_i('CFS', 'CFE_ES_HKPACKET', 'SYSLOGMODE'),
    erlog_index: tlm_i('CFS', 'CFE_ES_HKPACKET', 'ERLOGINDEX'),
    erlog_entries: tlm_i('CFS', 'CFE_ES_HKPACKET', 'ERLOGENTRIES'),
    registered_external_apps: tlm_i('CFS', 'CFE_ES_HKPACKET', 'REGISTEREDEXTERNALAPPS'),
    registered_tasks: tlm_i('CFS', 'CFE_ES_HKPACKET', 'REGISTEREDTASKS'),
    processor_resets: tlm_i('CFS', 'CFE_ES_HKPACKET', 'PROCESSORRESETS')
  }
end

def read_es_one_app_stale_ok
  {
    app_id: tlm_i('CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_APPID'),
    type: tlm_i('CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_TYPE'),
    name: clean_string(tlm('CFS CFE_ES_ONEAPPTLM APPINFO_NAME')),
    entry_point: clean_string(tlm('CFS CFE_ES_ONEAPPTLM APPINFO_ENTRYPOINT')),
    filename: clean_string(tlm('CFS CFE_ES_ONEAPPTLM APPINFO_FILENAME')),
    stack_size: tlm_i('CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_STACKSIZE'),
    module_id: tlm_i('CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_MODULEID'),
    start_address: tlm_i('CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_STARTADDRESS'),
    exception_action: tlm_i('CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_EXCEPTIONACTION'),
    priority: tlm_i('CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_PRIORITY'),
    main_task_id: tlm_i('CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_MAINTASKID'),
    execution_counter: tlm_i('CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_EXECUTIONCOUNTER'),
    main_task_name: clean_string(tlm('CFS CFE_ES_ONEAPPTLM APPINFO_MAINTASKNAME')),
    child_task_count: tlm_i('CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_NUMOFCHILDTASKS')
  }
end

def es_query_one_app(app_name)
  route = ensure_cfs_telemetry_route(ES_ONE_APP_MID, 16)
  command = cmd_first([
                        "CFE CFE_ES_QUERY_ONE with APPLICATION #{app_name}",
                        "CFS CFE_ES_QUERY_ONE with APPLICATION #{app_name}"
                      ])
  sleep(0.6)
  state = read_es_one_app_stale_ok
  {
    ok: command[:ok] && state[:name].to_s == app_name,
    route: route,
    command: command,
    state: state
  }
rescue Exception => error
  { ok: false, route: route, command: command, error_class: error.class.to_s, error: error.message }
end

def read_evs
  {
    cmd_count: tlm_i('CFS', 'CFE_EVS_TLMPKT', 'COMMANDCOUNTER'),
    err_count: tlm_i('CFS', 'CFE_EVS_TLMPKT', 'COMMANDERRCOUNTER'),
    message_format_mode: tlm_i('CFS', 'CFE_EVS_TLMPKT', 'MESSAGEFORMATMODE'),
    message_trunc_count: tlm_i('CFS', 'CFE_EVS_TLMPKT', 'MESSAGETRUNCCOUNTER'),
    unregistered_app_count: tlm_i('CFS', 'CFE_EVS_TLMPKT', 'UNREGISTEREDAPPCOUNTER'),
    output_port: tlm_i('CFS', 'CFE_EVS_TLMPKT', 'OUTPUTPORT'),
    log_full_flag: tlm_i('CFS', 'CFE_EVS_TLMPKT', 'LOGFULLFLAG'),
    log_mode: tlm_i('CFS', 'CFE_EVS_TLMPKT', 'LOGMODE'),
    message_send_count: tlm_i('CFS', 'CFE_EVS_TLMPKT', 'MESSAGESENDCOUNTER'),
    log_overflow_count: tlm_i('CFS', 'CFE_EVS_TLMPKT', 'LOGOVERFLOWCOUNTER'),
    log_enabled: tlm_i('CFS', 'CFE_EVS_TLMPKT', 'LOGENABLED')
  }
end

def delta(after, before, key)
  return nil unless after && before

  after[key].to_i - before[key].to_i
end

def clean_string(value)
  value.to_s.delete("\u0000").strip
end

def read_evs_event_packet
  {
    sequence: tlm_i('CFS', 'CFE_EVS_PACKET', 'CCSDS_SEQUENCE'),
    app_name: clean_string(tlm('CFS CFE_EVS_PACKET PACKETID_APPNAME')),
    event_id: tlm_i('CFS', 'CFE_EVS_PACKET', 'PACKETID_EVENTID'),
    event_type: tlm_i('CFS', 'CFE_EVS_PACKET', 'PACKETID_EVENTTYPE'),
    message: clean_string(tlm('CFS CFE_EVS_PACKET MESSAGE'))
  }
end

def evs_flood_event?(event)
  return false unless event

  event[:app_name] == APP_NAME &&
    event[:event_id] >= EVS_EVENT_FLOOD_EID_BASE &&
    event[:event_id] < EVS_EVENT_FLOOD_EID_BASE + EVS_EVENT_FLOOD_EID_COUNT &&
    event[:message].include?('SP003: EVS burst event')
end

def es_noop_event?(event)
  return false unless event

  event[:app_name] == 'CFE_ES' &&
    event[:event_id] == 3 &&
    event[:message].include?('No-op command')
end

def fm_lifecycle_event?(event)
  return false unless event

  message = event[:message].to_s.upcase
  event[:app_name] == 'CFE_ES' &&
    message.include?(FM_APP_NAME) &&
    (message.include?('RESTART') || message.include?('RELOAD') || message.include?('DELETE') ||
     message.include?('START') || message.include?('STOP'))
end

def event_at_or_after?(event, timestamp)
  Time.parse(event[:at]) >= timestamp
rescue Exception
  true
end

def collect_evs_events_during(duration_seconds, interval = 0.02)
  samples = []
  errors = []
  started = Time.now

  thread = Thread.new do
    while Time.now - started < duration_seconds
      begin
        event = read_evs_event_packet
        samples << event.merge(at: Time.now.utc.iso8601)
      rescue Exception => error
        errors << { error_class: error.class.to_s, error: error.message }
      end
      sleep(interval)
    end
  end

  { thread: thread, samples: samples, errors: errors }
end

def capture_es_noop_event(duration_seconds = EVS_SENTINEL_CAPTURE_SECONDS)
  capture = collect_evs_events_during(duration_seconds)
  sleep(0.1)
  sent_at = Time.now
  command = cmd_first(ES_NOOP_CANDIDATES)
  capture[:thread].join

  events = capture[:samples].select { |event| es_noop_event?(event) && event_at_or_after?(event, sent_at) }
  first_event = events.first
  latency = first_event ? Time.parse(first_event[:at]) - sent_at : nil

  {
    command: command,
    observed: !first_event.nil?,
    latency_seconds: latency,
    event: first_event,
    event_count: events.length,
    sample_count: capture[:samples].length,
    errors: capture[:errors].first(5)
  }
end

def run_event_flood_with_noop_sentinel(before_sp003)
  capture = collect_evs_events_during(EVS_ATTACK_CAPTURE_SECONDS)
  sleep(0.1)
  attack = sp003_run_profile(PROFILE_IDS[:event_burst], [EVS_EVENT_FLOOD_COUNT, EVS_EVENT_FLOOD_DELAY_MS])
  sleep(0.2)
  noop_sent_at = Time.now
  noop = cmd_first(ES_NOOP_CANDIDATES)
  observed = wait_sp003_observation(before_sp003, 8.0) do |state|
    state && state[:event_burst_count] > before_sp003[:event_burst_count]
  end
  capture[:thread].join

  noop_events = capture[:samples].select { |event| es_noop_event?(event) }
  flood_events = capture[:samples].select { |event| evs_flood_event?(event) }
  unique_flood_events = flood_events.uniq { |event| [event[:sequence], event[:event_id], event[:message]] }
  first_noop = noop_events.find { |event| event_at_or_after?(event, noop_sent_at) }
  noop_latency = first_noop ? Time.parse(first_noop[:at]) - noop_sent_at : nil

  {
    attack: attack,
    noop: noop,
    wait: observed,
    noop_observed: !first_noop.nil?,
    noop_latency_seconds: noop_latency,
    noop_event: first_noop,
    noop_event_count: noop_events.length,
    flood_event_count: unique_flood_events.length,
    sample_count: capture[:samples].length,
    errors: capture[:errors].first(5),
    flood_samples: unique_flood_events.first(10)
  }
end

def remove_file_if_present(path)
  File.delete(path) if File.exist?(path)
  { ok: true, path: path }
rescue Exception => error
  { ok: false, path: path, error_class: error.class.to_s, error: error.message }
end

def read_syslog_dump(path)
  data = File.binread(path)
  {
    ok: true,
    path: path,
    bytes: data.bytesize,
    sp003_pressure_entries: data.scan(/SP003: syslog pressure entry/).length,
    sp003_profile_entries: data.scan(/SP003: profile 22 executed/).length,
    sp003_sentinel_entries: data.scan(/SP003: syslog sentinel token/).length,
    text_preview: data[-512, 512].to_s
  }
rescue Exception => error
  { ok: false, path: path, error_class: error.class.to_s, error: error.message }
end

def read_sch
  {
    slot_processed_count: tlm_i('CFS', 'SCH_HKPACKET', 'SLOTSPROCESSEDCOUNT'),
    skipped_slots_count: tlm_i('CFS', 'SCH_HKPACKET', 'SKIPPEDSLOTSCOUNT'),
    multiple_slots_count: tlm_i('CFS', 'SCH_HKPACKET', 'MULTIPLESLOTSCOUNT'),
    same_slot_count: tlm_i('CFS', 'SCH_HKPACKET', 'SAMESLOTCOUNT'),
    activity_success_count: tlm_i('CFS', 'SCH_HKPACKET', 'SCHEDULEACTIVITYSUCCESSCOUNT'),
    activity_failure_count: tlm_i('CFS', 'SCH_HKPACKET', 'SCHEDULEACTIVITYFAILURECOUNT'),
    table_pass_count: tlm_i('CFS', 'SCH_HKPACKET', 'TABLEPASSCOUNT'),
    next_slot_number: tlm_i('CFS', 'SCH_HKPACKET', 'NEXTSLOTNUMBER')
  }
end

def request_fm_hk
  cmd_optional('CFS FM_SEND_HK')
  sleep(0.35)
end

def read_fm_stale_ok
  {
    cmd_count: tlm_i('CFS', 'FM_HOUSEKEEPINGPKT', 'COMMANDCOUNTER'),
    err_count: tlm_i('CFS', 'FM_HOUSEKEEPINGPKT', 'COMMANDERRCOUNTER'),
    child_count: tlm_i('CFS', 'FM_HOUSEKEEPINGPKT', 'CHILDCMDCOUNTER'),
    child_err_count: tlm_i('CFS', 'FM_HOUSEKEEPINGPKT', 'CHILDCMDERRCOUNTER')
  }
end

def read_fm
  request_fm_hk
  read_fm_stale_ok
end

def fm_noop
  cmd_optional('CFS FM_NOOP')
end

def wait_fm_counter_increase(before, timeout = 6.0)
  errors = []
  min_count = before ? before[:cmd_count].to_i : -1

  result = wait_until(timeout, 0.5) do
    begin
      state = read_fm
      { matched: state[:cmd_count] != min_count, state: state }
    rescue Exception => error
      errors << { error_class: error.class.to_s, error: error.message }
      { matched: false, state: nil }
    end
  end

  result[:errors] = errors unless errors.empty?
  result
end

def fm_alive_probe(timeout = 6.0)
  before = read_fm_stale_ok rescue nil
  noop = fm_noop
  wait = wait_fm_counter_increase(before, timeout)
  {
    alive: noop[:ok] && wait[:matched],
    noop: noop,
    before: before,
    after: wait[:state],
    wait: wait
  }
end

def ensure_fm_telemetry_route
  ensure_cfs_telemetry_route(FM_HK_MID, 16)
end

def file_digest(path)
  return nil unless File.exist?(path)

  Digest::SHA256.file(path).hexdigest
end

def backup_fm_so
  unless File.exist?(FM_HOST_PATH)
    return { ok: false, source: FM_HOST_PATH, backup: FM_BACKUP_HOST_PATH, reason: 'FM shared object is missing before attack' }
  end

  FileUtils.cp(FM_HOST_PATH, FM_BACKUP_HOST_PATH)
  {
    ok: File.exist?(FM_BACKUP_HOST_PATH),
    source: FM_HOST_PATH,
    backup: FM_BACKUP_HOST_PATH,
    source_size: File.size(FM_HOST_PATH),
    backup_size: File.size(FM_BACKUP_HOST_PATH),
    source_sha256: file_digest(FM_HOST_PATH),
    backup_sha256: file_digest(FM_BACKUP_HOST_PATH)
  }
rescue Exception => error
  { ok: false, source: FM_HOST_PATH, backup: FM_BACKUP_HOST_PATH, error_class: error.class.to_s, error: error.message }
end

def restore_fm_so_from_backup
  unless File.exist?(FM_BACKUP_HOST_PATH)
    return { ok: false, source: FM_HOST_PATH, backup: FM_BACKUP_HOST_PATH, reason: 'FM backup is missing' }
  end

  FileUtils.cp(FM_BACKUP_HOST_PATH, FM_HOST_PATH)
  {
    ok: File.exist?(FM_HOST_PATH),
    source: FM_HOST_PATH,
    backup: FM_BACKUP_HOST_PATH,
    source_size: File.size(FM_HOST_PATH),
    backup_size: File.size(FM_BACKUP_HOST_PATH),
    source_sha256: file_digest(FM_HOST_PATH),
    backup_sha256: file_digest(FM_BACKUP_HOST_PATH)
  }
rescue Exception => error
  { ok: false, source: FM_HOST_PATH, backup: FM_BACKUP_HOST_PATH, error_class: error.class.to_s, error: error.message }
end

def remove_fm_backup
  if File.exist?(FM_BACKUP_HOST_PATH)
    File.delete(FM_BACKUP_HOST_PATH)
    { ok: true, removed: true, backup: FM_BACKUP_HOST_PATH }
  else
    { ok: true, removed: false, backup: FM_BACKUP_HOST_PATH }
  end
rescue Exception => error
  { ok: false, backup: FM_BACKUP_HOST_PATH, error_class: error.class.to_s, error: error.message }
end

def start_fm_app(timeout = 15.0)
  route = ensure_fm_telemetry_route
  alive_before = fm_alive_probe(3.0)
  return { ok: true, action: 'already_alive', route: route, alive_before: alive_before } if alive_before[:alive]

  start = cmd_first(START_FM_CANDIDATES)
  sleep(2.0)
  alive_after = fm_alive_probe(timeout)
  query_after = es_query_one_app(FM_APP_NAME)
  {
    ok: alive_after[:alive] || query_after[:ok],
    action: 'start_app',
    route: route,
    command: start,
    alive_before: alive_before,
    alive_after: alive_after,
    query_after: query_after
  }
end

def restore_fm_app
  restore_file = restore_fm_so_from_backup
  start = start_fm_app
  { ok: restore_file[:ok] && start[:ok], restore_file: restore_file, start: start }
end

def sample_sch(duration_seconds, interval = SCH_CPU_SAMPLE_INTERVAL)
  started = Time.now
  samples = []

  loop do
    timestamp = Time.now
    begin
      samples << { at: timestamp.utc.iso8601, elapsed: timestamp - started, state: read_sch }
    rescue Exception => error
      samples << { at: timestamp.utc.iso8601, elapsed: timestamp - started, error_class: error.class.to_s, error: error.message }
    end

    break if Time.now - started >= duration_seconds
    sleep(interval)
  end

  samples
end

def sch_first_valid(samples)
  samples.find { |sample| sample[:state] }
end

def sch_last_valid(samples)
  samples.reverse.find { |sample| sample[:state] }
end

def sch_delta(samples, key)
  first = sch_first_valid(samples)
  last = sch_last_valid(samples)
  return nil unless first && last

  last[:state][key].to_i - first[:state][key].to_i
end

def sch_duration(samples)
  first = sch_first_valid(samples)
  last = sch_last_valid(samples)
  return nil unless first && last

  elapsed = last[:elapsed].to_f - first[:elapsed].to_f
  elapsed.positive? ? elapsed : nil
end

def sch_slot_rate(samples)
  delta = sch_delta(samples, :slot_processed_count)
  duration = sch_duration(samples)
  return nil unless delta && duration

  delta.to_f / duration
end

def sch_anomaly_delta(samples)
  {
    skipped_slots_count: sch_delta(samples, :skipped_slots_count),
    multiple_slots_count: sch_delta(samples, :multiple_slots_count),
    same_slot_count: sch_delta(samples, :same_slot_count),
    activity_failure_count: sch_delta(samples, :activity_failure_count)
  }
end

def sch_any_anomaly_increased?(deltas)
  deltas.values.any? { |value| !value.nil? && value.positive? }
end

def request_sp003_hk
  cmd_optional('CFS SP003_REQ_HK')
  sleep(0.25)
end

def read_sp003_stale_ok
  request_sp003_hk
  {
    cmd_count: tlm_i('CFS', 'SP003_HK_TLM', 'COMMANDCOUNT'),
    err_count: tlm_i('CFS', 'SP003_HK_TLM', 'COMMANDERRCOUNT'),
    last_profile_id: tlm_i('CFS', 'SP003_HK_TLM', 'LASTPROFILEID'),
    last_status: tlm_i('CFS', 'SP003_HK_TLM', 'LASTSTATUS'),
    profiles_executed: tlm_i('CFS', 'SP003_HK_TLM', 'PROFILESEXECUTED'),
    boot_count: tlm_i('CFS', 'SP003_HK_TLM', 'BOOTCOUNT'),
    heartbeat: tlm_i('CFS', 'SP003_HK_TLM', 'HEARTBEAT'),
    self_exit_count: tlm_i('CFS', 'SP003_HK_TLM', 'SELFEXITCOUNT'),
    crash_request_count: tlm_i('CFS', 'SP003_HK_TLM', 'CRASHREQUESTCOUNT'),
    abort_request_count: tlm_i('CFS', 'SP003_HK_TLM', 'ABORTREQUESTCOUNT'),
    restart_api_count: tlm_i('CFS', 'SP003_HK_TLM', 'RESTARTAPICOUNT'),
    delete_api_count: tlm_i('CFS', 'SP003_HK_TLM', 'DELETEAPICOUNT'),
    reload_api_count: tlm_i('CFS', 'SP003_HK_TLM', 'RELOADAPICOUNT'),
    busy_loop_count: tlm_i('CFS', 'SP003_HK_TLM', 'BUSYLOOPCOUNT'),
    event_burst_count: tlm_i('CFS', 'SP003_HK_TLM', 'EVENTBURSTCOUNT'),
    syslog_burst_count: tlm_i('CFS', 'SP003_HK_TLM', 'SYSLOGBURSTCOUNT'),
    startup_fault_remaining: tlm_i('CFS', 'SP003_HK_TLM', 'STARTUPFAULTREMAINING'),
    startup_fault_mode: tlm_i('CFS', 'SP003_HK_TLM', 'STARTUPFAULTMODE'),
    last_run_status: tlm_i('CFS', 'SP003_HK_TLM', 'LASTRUNSTATUS')
  }
end

def wait_sp003_fresh(previous = nil, timeout = 8.0)
  min_heartbeat = previous ? previous[:heartbeat].to_i : -1
  min_boot = previous ? previous[:boot_count].to_i : -1
  errors = []

  result = wait_until(timeout, 0.5) do
    begin
      state = read_sp003_stale_ok
      fresh = previous.nil? || state[:heartbeat] > min_heartbeat || state[:boot_count] > min_boot
      { matched: fresh, state: state, fresh: fresh }
    rescue Exception => error
      errors << { error_class: error.class.to_s, error: error.message }
      { matched: false, state: nil, fresh: false }
    end
  end

  result[:errors] = errors unless errors.empty?
  result
end

def sp003_alive?(before = nil, timeout = 3.0)
  wait_sp003_fresh(before, timeout)[:matched]
end


def wait_sp003_observation(before = nil, timeout = 8.0)
  errors = []

  result = wait_until(timeout, 0.5) do
    begin
      state = read_sp003_stale_ok
      matched = yield(state)
      { matched: matched, state: state }
    rescue Exception => error
      errors << { error_class: error.class.to_s, error: error.message }
      { matched: false, state: nil }
    end
  end

  result[:errors] = errors unless errors.empty?
  result
end


def ensure_cfs_telemetry_route(stream_mid, buffer_limit = 16)
  return { ok: false, skipped: true, reason: 'SP003_TO_LAB_ADD_PKT command not loaded' } unless command_available?('CFS', 'SP003_TO_LAB_ADD_PKT')

  add = cmd_optional("CFS SP003_TO_LAB_ADD_PKT with STREAM #{stream_mid}, PRIORITY 0, RELIABILITY 0, BUFLIMIT #{buffer_limit}, SPARE 0")
  sleep(0.5)
  add
end

def ensure_sp003_telemetry_route
  ensure_cfs_telemetry_route(SP003_HK_MID, 16)
end

def sp003_start(timeout = 45.0)
  baseline = nil
  attempts = []
  deadline = Time.now + timeout
  last_wait = nil

  begin
    ensure_sp003_telemetry_route
    baseline = read_sp003_stale_ok
    return { ok: true, action: 'already_alive', state: baseline, attempts: attempts } if sp003_alive?(baseline, 2.0)
  rescue Exception
    baseline = nil
  end

  while Time.now < deadline
    start_result = cmd_first(START_APP_CANDIDATES)
    attempts << { action: 'start_app', command: start_result, at: Time.now.utc.iso8601 }
    sleep(1.0)
    begin
      ensure_sp003_telemetry_route
    rescue Exception
      nil
    end
    last_wait = wait_sp003_fresh(baseline, 6.0)
    return { ok: true, action: 'start_app', command: start_result, state: last_wait[:state], attempts: attempts } if last_wait[:matched]

    restart_result = cmd_first(RESTART_APP_CANDIDATES)
    attempts << { action: 'restart_app', command: restart_result, at: Time.now.utc.iso8601 }
    sleep(1.0)
    begin
      ensure_sp003_telemetry_route
    rescue Exception
      nil
    end
    last_wait = wait_sp003_fresh(baseline, 6.0)
    return { ok: true, action: 'restart_app', command: restart_result, state: last_wait[:state], attempts: attempts } if last_wait[:matched]
  end

  { ok: false, action: 'start_failed', attempts: attempts, wait: last_wait }
end

def sp003_restart_and_wait(before = nil, timeout = 10.0)
  result = cmd_first(RESTART_APP_CANDIDATES)
  sleep(1.0)
  fresh = wait_sp003_fresh(before, timeout)
  { ok: fresh[:matched], command: result, state: fresh[:state], wait: fresh }
end

def sp003_stop
  cmd_first(STOP_APP_CANDIDATES)
end

def pad_string(value, _length)
  value.to_s
end

def sp003_run_profile(profile_id, args = [], target_app = '', reload_path = '')
  full_args = args + Array.new(4 - args.length, 0)
  # COSMOS command strings cannot leave the final STRING parameters blank; blank values are treated as missing args.
  target = pad_string(target_app.to_s.empty? ? APP_NAME : target_app, 32)
  reload = pad_string(reload_path.to_s.empty? ? APP_FILE : reload_path, 64)
  command = "CFS SP003_RUN_PROFILE with PROFILEID #{profile_id}, FLAGS 0, ARG1 #{full_args[0]}, ARG2 #{full_args[1]}, ARG3 #{full_args[2]}, ARG4 #{full_args[3]}, TARGETAPP #{target}, RELOADPATH #{reload}"
  cmd(command)
  { ok: true, command: command, profile_id: profile_id, args: full_args, target_app: target, reload_path: reload }
rescue Exception => error
  { ok: false, profile_id: profile_id, args: full_args, target_app: target_app, reload_path: reload_path, error_class: error.class.to_s, error: error.message }
end

def clear_persistent_state
  before = nil
  begin
    before = read_sp003_stale_ok
  rescue Exception
    before = nil
  end
  sp003_run_profile(PROFILE_IDS[:clear_persistent_state])
  wait_sp003_fresh(before, 4.0)
end

def disarm_startup_fault
  before = nil
  begin
    before = read_sp003_stale_ok
  rescue Exception
    before = nil
  end
  sp003_run_profile(PROFILE_IDS[:disarm_startup_fault])
  wait_sp003_fresh(before, 4.0)
rescue Exception
  sp003_start
end

def evidence_all?(hash)
  hash.values.all? { |value| value == true }
end

def verdict_score(status, verdict, evidence, extra = {})
  {
    status: status,
    verdict: verdict,
    attack_success: verdict == 'attack_success',
    evidence: evidence
  }.merge(extra)
end

def run_fm_restart_or_reload_lifecycle(profile_id, api_counter_key, action_name, reload_path = '')
  before_sp003 = read_sp003_stale_ok
  route_fm = ensure_fm_telemetry_route
  route_es_one = ensure_cfs_telemetry_route(ES_ONE_APP_MID, 16)
  route_evs_event = ensure_cfs_telemetry_route(EVS_EVENT_MID, 64)
  backup = backup_fm_so
  baseline = fm_alive_probe
  raise SkipProfile, 'FM is not alive before lifecycle attack' unless baseline[:alive]

  before_fm = baseline[:after]
  before_one = es_query_one_app(FM_APP_NAME)
  before_es = read_es rescue nil
  capture = collect_evs_events_during(8.0, 0.05)
  sleep(0.1)
  attack = sp003_run_profile(profile_id, [1], FM_APP_NAME, reload_path)
  observed = wait_sp003_observation(before_sp003, 8.0) do |state|
    state && state[api_counter_key].to_i > before_sp003[api_counter_key].to_i
  end
  sleep(1.5)
  after_probe = fm_alive_probe(8.0)
  after_one = es_query_one_app(FM_APP_NAME)
  capture[:thread].join
  after_fm = after_probe[:after]
  after_sp003 = observed[:state]
  after_es = read_es rescue nil

  lifecycle_events = capture[:samples].select { |event| fm_lifecycle_event?(event) }
  fm_counter_reset_or_decreased =
    before_fm && after_fm &&
    before_fm[:cmd_count].to_i.positive? &&
    after_fm[:cmd_count].to_i < before_fm[:cmd_count].to_i
  es_one_app_still_reports_fm = before_one[:ok] && after_one[:ok]
  es_one_app_identity_changed =
    es_one_app_still_reports_fm &&
    (before_one[:state][:main_task_id] != after_one[:state][:main_task_id] ||
     before_one[:state][:module_id] != after_one[:state][:module_id] ||
     before_one[:state][:start_address] != after_one[:state][:start_address] ||
     before_one[:state][:execution_counter] > after_one[:state][:execution_counter])
  payload_executed = attack[:ok] && observed[:matched] && after_sp003 && after_sp003[:last_status].to_i == 0
  fm_lifecycle_impact_observed = fm_counter_reset_or_decreased || es_one_app_identity_changed || !lifecycle_events.empty?
  fm_recovered_after_lifecycle = after_probe[:alive] || after_one[:ok]
  backup_cleanup =
    if backup[:ok] && fm_recovered_after_lifecycle
      remove_fm_backup
    else
      { ok: true, skipped: true, reason: 'kept FM backup because lifecycle recovery was not confirmed' }
    end

  evidence = {
    fm_hk_route_added: route_fm[:ok],
    es_one_app_route_added: route_es_one[:ok],
    evs_event_route_added: route_evs_event[:ok],
    fm_so_backed_up: backup[:ok],
    fm_alive_before_attack: baseline[:alive],
    es_one_app_reported_fm_before: before_one[:ok],
    es_one_app_reported_fm_after: after_one[:ok],
    command_sent: attack[:ok],
    payload_executed: payload_executed,
    sp003_api_counter_increased: observed[:matched],
    sp003_last_status_success: after_sp003 && after_sp003[:last_status].to_i == 0,
    fm_lifecycle_impact_observed: fm_lifecycle_impact_observed,
    fm_counter_reset_or_decreased: fm_counter_reset_or_decreased,
    es_one_app_identity_changed: es_one_app_identity_changed,
    fm_lifecycle_event_observed: !lifecycle_events.empty?,
    fm_recovered_after_lifecycle: fm_recovered_after_lifecycle,
    fm_backup_removed_after_recovery: backup_cleanup[:ok] && backup_cleanup[:removed] != false,
    action: action_name
  }
  verdict =
    if backup[:ok] && payload_executed && fm_lifecycle_impact_observed && fm_recovered_after_lifecycle
      'attack_success'
    elsif payload_executed && fm_recovered_after_lifecycle
      'inconclusive_no_fm_lifecycle_impact'
    elsif !backup[:ok]
      'inconclusive_fm_backup_failed'
    else
      'inconclusive_payload_not_confirmed'
    end

  verdict_score(verdict == 'attack_success' ? 'PASS' : 'FAIL', verdict, evidence,
                before: { sp003: before_sp003, fm: before_fm, es: before_es },
                after: { sp003: after_sp003, fm: after_fm, es: after_es },
                wait: observed, route_fm: route_fm, route_es_one: route_es_one, route_evs_event: route_evs_event,
                backup: backup, baseline: baseline, after_probe: after_probe,
                backup_cleanup: backup_cleanup, before_one_app: before_one, after_one_app: after_one,
                lifecycle_events: lifecycle_events.first(10), lifecycle_event_errors: capture[:errors].first(5),
                attack: attack)
end

def run_fm_delete_then_restore_lifecycle
  before_sp003 = read_sp003_stale_ok
  route_fm = ensure_fm_telemetry_route
  route_es_one = ensure_cfs_telemetry_route(ES_ONE_APP_MID, 16)
  route_evs_event = ensure_cfs_telemetry_route(EVS_EVENT_MID, 64)
  backup = backup_fm_so
  baseline = fm_alive_probe
  raise SkipProfile, 'FM is not alive before lifecycle attack' unless baseline[:alive]

  before_fm = baseline[:after]
  before_one = es_query_one_app(FM_APP_NAME)
  before_es = read_es rescue nil
  capture = collect_evs_events_during(8.0, 0.05)
  sleep(0.1)
  attack = sp003_run_profile(PROFILE_IDS[:delete_target_api], [], FM_APP_NAME)
  observed = wait_sp003_observation(before_sp003, 8.0) do |state|
    state && state[:delete_api_count].to_i > before_sp003[:delete_api_count].to_i
  end
  sleep(1.5)
  after_delete_probe = fm_alive_probe(4.0)
  after_delete_one = es_query_one_app(FM_APP_NAME)
  after_delete_es = read_es rescue nil
  restore = restore_fm_app
  after_restore_probe = fm_alive_probe(8.0)
  after_restore_one = es_query_one_app(FM_APP_NAME)
  capture[:thread].join

  after_sp003 = observed[:state]
  lifecycle_events = capture[:samples].select { |event| fm_lifecycle_event?(event) }
  fm_unavailable_after_delete = !after_delete_probe[:alive]
  es_one_app_missing_or_stale_after_delete = before_one[:ok] && !after_delete_one[:ok]
  es_external_app_count_not_increased =
    before_es && after_delete_es &&
    after_delete_es[:registered_external_apps].to_i <= before_es[:registered_external_apps].to_i
  payload_executed = attack[:ok] && observed[:matched] && after_sp003 && after_sp003[:last_status].to_i == 0
  fm_restored_after_delete =
    restore[:restore_file] && restore[:restore_file][:ok] &&
    (restore[:ok] || after_restore_probe[:alive] || after_restore_one[:ok])
  backup_cleanup =
    if fm_restored_after_delete
      remove_fm_backup
    else
      { ok: true, skipped: true, reason: 'kept FM backup because restore was not confirmed' }
    end

  evidence = {
    fm_hk_route_added: route_fm[:ok],
    es_one_app_route_added: route_es_one[:ok],
    evs_event_route_added: route_evs_event[:ok],
    fm_so_backed_up: backup[:ok],
    fm_alive_before_attack: baseline[:alive],
    es_one_app_reported_fm_before: before_one[:ok],
    command_sent: attack[:ok],
    payload_executed: payload_executed,
    sp003_delete_counter_increased: observed[:matched],
    sp003_last_status_success: after_sp003 && after_sp003[:last_status].to_i == 0,
    fm_unavailable_after_delete: fm_unavailable_after_delete,
    es_one_app_missing_or_stale_after_delete: es_one_app_missing_or_stale_after_delete,
    fm_lifecycle_event_observed: !lifecycle_events.empty?,
    es_external_app_count_not_increased: es_external_app_count_not_increased,
    fm_so_restored_from_backup: restore[:restore_file] && restore[:restore_file][:ok],
    fm_restored_after_delete: fm_restored_after_delete,
    es_one_app_reported_fm_after_restore: after_restore_one[:ok],
    fm_backup_removed_after_restore: backup_cleanup[:ok] && backup_cleanup[:removed] != false
  }
  verdict =
    if backup[:ok] && payload_executed && fm_unavailable_after_delete && fm_restored_after_delete
      'attack_success'
    elsif payload_executed && !fm_unavailable_after_delete
      'inconclusive_no_fm_availability_impact'
    elsif !backup[:ok]
      'inconclusive_fm_backup_failed'
    elsif !fm_restored_after_delete
      'profile_bug_restore_failed'
    else
      'inconclusive_payload_not_confirmed'
    end

  verdict_score(verdict == 'attack_success' ? 'PASS' : 'FAIL', verdict, evidence,
                before: { sp003: before_sp003, fm: before_fm, es: before_es },
                after_delete: { sp003: after_sp003, fm_probe: after_delete_probe, es: after_delete_es },
                restore: restore, after_restore_probe: after_restore_probe,
                wait: observed, route_fm: route_fm, route_es_one: route_es_one, route_evs_event: route_evs_event,
                backup: backup, backup_cleanup: backup_cleanup, baseline: baseline, lifecycle_events: lifecycle_events.first(10),
                before_one_app: before_one, after_delete_one_app: after_delete_one, after_restore_one_app: after_restore_one,
                lifecycle_event_errors: capture[:errors].first(5), attack: attack)
end

def make_profiles
  [
    {
      profile_id: 'sp003_noop_baseline',
      name: 'noop_baseline',
      risk: 'safe',
      target: 'SP003',
      category: 'baseline',
      run: lambda do
        before = read_sp003_stale_ok
        noop = cmd_optional('CFS SP003_NOOP')
        fresh = wait_sp003_fresh(before, 5.0)
        evidence = {
          command_sent: noop[:ok],
          hk_fresh_after_noop: fresh[:matched],
          command_counter_increased: fresh[:state] && fresh[:state][:cmd_count] > before[:cmd_count]
        }
        verdict_score(evidence_all?(evidence) ? 'PASS' : 'FAIL', evidence_all?(evidence) ? 'attack_success' : 'profile_bug', evidence,
                      before: before, after: fresh[:state], attack: noop)
      end
    },
    {
      profile_id: 'sp003_sch_cpu_starvation_8000ms',
      name: 'sch_cpu_starvation_8000ms',
      risk: 'safe',
      target: 'SCH',
      category: 'scheduler_cpu_starvation',
      run: lambda do
        before_sp003 = read_sp003_stale_ok
        baseline_samples = sample_sch(SCH_CPU_BASELINE_SECONDS)
        baseline_rate = sch_slot_rate(baseline_samples)

        attack = sp003_run_profile(PROFILE_IDS[:busy_loop_ms], [SCH_CPU_ATTACK_MS])
        attack_samples = sample_sch(SCH_CPU_ATTACK_SECONDS)
        attack_rate = sch_slot_rate(attack_samples)
        attack_anomaly_deltas = sch_anomaly_delta(attack_samples)
        observed = wait_sp003_observation(before_sp003, 8.0) do |state|
          state && state[:busy_loop_count] > before_sp003[:busy_loop_count]
        end
        after_sp003 = observed[:state]
        recovery_samples = sample_sch(SCH_CPU_RECOVERY_SECONDS)
        recovery_rate = sch_slot_rate(recovery_samples)

        rate_ratio = (baseline_rate && attack_rate && baseline_rate.positive?) ? attack_rate / baseline_rate : nil
        scheduler_rate_degraded = rate_ratio && rate_ratio < SCH_CPU_RATE_RATIO_THRESHOLD
        scheduler_anomaly_counter_increased = sch_any_anomaly_increased?(attack_anomaly_deltas)
        scheduler_impact_observed = scheduler_rate_degraded || scheduler_anomaly_counter_increased
        payload_executed = attack[:ok] && after_sp003 && after_sp003[:busy_loop_count] > before_sp003[:busy_loop_count]

        evidence = {
          command_sent: attack[:ok],
          payload_executed: payload_executed,
          scheduler_impact_observed: scheduler_impact_observed,
          scheduler_rate_degraded: scheduler_rate_degraded,
          scheduler_anomaly_counter_increased: scheduler_anomaly_counter_increased,
          baseline_slot_rate: baseline_rate,
          attack_slot_rate: attack_rate,
          attack_to_baseline_rate_ratio: rate_ratio,
          rate_ratio_threshold: SCH_CPU_RATE_RATIO_THRESHOLD,
          recovery_slot_rate: recovery_rate,
          attack_anomaly_deltas: attack_anomaly_deltas
        }
        verdict = payload_executed && scheduler_impact_observed ? 'attack_success' : 'inconclusive_no_scheduler_impact'
        verdict_score(verdict == 'attack_success' ? 'PASS' : 'FAIL', verdict, evidence,
                      before: { sp003: before_sp003, sch: sch_first_valid(baseline_samples) && sch_first_valid(baseline_samples)[:state] },
                      after: { sp003: after_sp003, sch: sch_last_valid(attack_samples) && sch_last_valid(attack_samples)[:state] },
                      baseline_samples: baseline_samples, attack_samples: attack_samples, recovery_samples: recovery_samples,
                      attack: attack)
      end
    },
    {
      profile_id: 'sp003_evs_event_flood_200',
      name: 'evs_event_flood_200',
      risk: 'safe',
      target: 'SP003/EVS',
      category: 'evs_observability_pressure',
      run: lambda do
        before_sp003 = read_sp003_stale_ok
        route_evs = ensure_cfs_telemetry_route(EVS_HK_MID, 16)
        route_evs_event = ensure_cfs_telemetry_route(EVS_EVENT_MID, 64)
        clear_evs_log = cmd_first(EVS_CLEAR_LOG_CANDIDATES)
        sleep(1.0)
        baseline_sentinel = capture_es_noop_event
        before_evs = read_evs
        attack_observation = run_event_flood_with_noop_sentinel(before_sp003)
        after_sp003 = attack_observation[:wait][:state]
        sleep(1.0)
        after_evs = read_evs
        recovery_sentinel = capture_es_noop_event

        message_send_delta = delta(after_evs, before_evs, :message_send_count)
        trunc_delta = delta(after_evs, before_evs, :message_trunc_count)
        overflow_delta = delta(after_evs, before_evs, :log_overflow_count)
        log_became_full = before_evs && after_evs && before_evs[:log_full_flag] == 0 && after_evs[:log_full_flag] != 0

        baseline_latency = baseline_sentinel[:latency_seconds]
        attack_latency = attack_observation[:noop_latency_seconds]
        attack_sentinel_lost = baseline_sentinel[:observed] && recovery_sentinel[:observed] && !attack_observation[:noop_observed]
        attack_sentinel_delayed =
          baseline_sentinel[:observed] && attack_observation[:noop_observed] && baseline_latency && attack_latency &&
          attack_latency >= EVS_SENTINEL_DELAY_SECONDS_THRESHOLD &&
          attack_latency >= baseline_latency * EVS_SENTINEL_DELAY_RATIO_THRESHOLD
        evs_pressure_counter_triggered =
          (trunc_delta && trunc_delta.positive?) ||
          (overflow_delta && overflow_delta.positive?) ||
          log_became_full
        evs_observability_degraded = attack_sentinel_lost || attack_sentinel_delayed || evs_pressure_counter_triggered
        sp003_event_counter_increased = after_sp003 && after_sp003[:event_burst_count] > before_sp003[:event_burst_count]
        payload_executed = attack_observation[:attack][:ok] &&
                           (sp003_event_counter_increased || attack_observation[:flood_event_count].positive? ||
                            (message_send_delta && message_send_delta.positive?))

        evidence = {
          command_sent: attack_observation[:attack][:ok],
          evs_hk_route_added: route_evs[:ok],
          evs_event_route_added: route_evs_event[:ok],
          evs_log_cleared_for_baseline: clear_evs_log[:ok],
          payload_executed: payload_executed,
          sp003_hk_recovered: attack_observation[:wait][:matched],
          sp003_event_counter_increased: sp003_event_counter_increased,
          evs_observability_degraded: evs_observability_degraded,
          baseline_es_noop_event_observed: baseline_sentinel[:observed],
          attack_es_noop_event_observed: attack_observation[:noop_observed],
          recovery_es_noop_event_observed: recovery_sentinel[:observed],
          attack_es_noop_event_lost: attack_sentinel_lost,
          attack_es_noop_event_delayed: attack_sentinel_delayed,
          baseline_es_noop_latency_seconds: baseline_latency,
          attack_es_noop_latency_seconds: attack_latency,
          recovery_es_noop_latency_seconds: recovery_sentinel[:latency_seconds],
          evs_pressure_counter_triggered: evs_pressure_counter_triggered,
          evs_event_packet_flood_count: attack_observation[:flood_event_count],
          evs_event_flood_delay_ms: EVS_EVENT_FLOOD_DELAY_MS,
          evs_message_send_delta: message_send_delta,
          evs_message_trunc_delta: trunc_delta,
          evs_log_overflow_delta: overflow_delta,
          evs_log_became_full: log_became_full,
          evs_output_port: after_evs && after_evs[:output_port],
          evs_log_enabled: after_evs && after_evs[:log_enabled],
          profile_execution_counter_increased: after_sp003 && after_sp003[:profiles_executed] > before_sp003[:profiles_executed]
        }
        verdict =
          if route_evs_event[:ok] && clear_evs_log[:ok] && payload_executed && evs_observability_degraded
            'attack_success'
          elsif route_evs_event[:ok] && clear_evs_log[:ok] && payload_executed
            'inconclusive_no_evs_observability_impact'
          elsif !route_evs_event[:ok]
            'inconclusive_evs_event_route_not_available'
          elsif !clear_evs_log[:ok]
            'inconclusive_evs_baseline_not_controlled'
          else
            'inconclusive_payload_not_confirmed'
          end
        verdict_score(verdict == 'attack_success' ? 'PASS' : 'FAIL', verdict, evidence,
                      before: { sp003: before_sp003, evs: before_evs },
                      after: { sp003: after_sp003, evs: after_evs }, wait: attack_observation[:wait],
                      route_evs: route_evs, route_evs_event: route_evs_event, clear_evs_log: clear_evs_log,
                      baseline_sentinel: baseline_sentinel, attack_observation: attack_observation,
                      recovery_sentinel: recovery_sentinel, attack: attack_observation[:attack])
      end
    },
    {
      profile_id: 'sp003_es_syslog_flood_200',
      name: 'es_syslog_flood_200',
      risk: 'safe',
      target: 'SP003/CFE_ES',
      category: 'es_syslog_availability_pressure',
      run: lambda do
        before_sp003 = read_sp003_stale_ok
        route_es = ensure_cfs_telemetry_route(ES_HK_MID, 16)
        remove_syslog_dump = remove_file_if_present(SYSLOG_DUMP_HOST_PATH)
        clear_syslog = cmd_first(ES_CLEAR_SYSLOG_CANDIDATES)
        sleep(1.0)
        sentinel_token = Time.now.utc.to_i
        sentinel = sp003_run_profile(PROFILE_IDS[:syslog_sentinel], [sentinel_token])
        sentinel_observed = wait_sp003_observation(before_sp003, 5.0) do |state|
          state && state[:last_profile_id] == PROFILE_IDS[:syslog_sentinel] && state[:profiles_executed] > before_sp003[:profiles_executed]
        end
        before_es = read_es
        attack = sp003_run_profile(PROFILE_IDS[:syslog_burst], [ES_SYSLOG_FLOOD_COUNT])
        observed = wait_sp003_observation(before_sp003, 8.0) do |state|
          state && state[:syslog_burst_count] > before_sp003[:syslog_burst_count]
        end
        after_sp003 = observed[:state]
        sleep(1.0)
        after_es = read_es
        write_syslog = cmd_first(ES_WRITE_SYSLOG_CANDIDATES)
        sleep(1.0)
        syslog_dump = read_syslog_dump(SYSLOG_DUMP_HOST_PATH)

        syslog_entries_delta = delta(after_es, before_es, :syslog_entries)
        syslog_bytes_delta = delta(after_es, before_es, :syslog_bytes_used)
        before_syslog_fill_ratio = (before_es && before_es[:syslog_size].to_i.positive?) ? before_es[:syslog_bytes_used].to_f / before_es[:syslog_size].to_f : nil
        syslog_fill_ratio = (after_es && after_es[:syslog_size].to_i.positive?) ? after_es[:syslog_bytes_used].to_f / after_es[:syslog_size].to_f : nil
        syslog_dump_pressure_observed = syslog_dump[:ok] && syslog_dump[:sp003_pressure_entries] >= ES_SYSLOG_ENTRY_DELTA_THRESHOLD
        syslog_dump_total_sp003_entries = syslog_dump[:ok] ? syslog_dump[:sp003_pressure_entries].to_i + syslog_dump[:sp003_sentinel_entries].to_i + syslog_dump[:sp003_profile_entries].to_i : 0
        syslog_dump_pressure_ratio = syslog_dump_total_sp003_entries.positive? ? syslog_dump[:sp003_pressure_entries].to_f / syslog_dump_total_sp003_entries : nil
        syslog_dump_pressure_dominates = syslog_dump_pressure_ratio && syslog_dump_pressure_ratio >= SYSLOG_PRESSURE_DOMINANCE_THRESHOLD
        sentinel_missing_from_dump = syslog_dump[:ok] && sentinel[:ok] && syslog_dump[:sp003_sentinel_entries].to_i == 0
        syslog_became_full_from_controlled_baseline =
          before_syslog_fill_ratio && syslog_fill_ratio &&
          before_syslog_fill_ratio < 0.30 && syslog_fill_ratio >= 0.80
        syslog_pressure_observed =
          syslog_dump_pressure_dominates ||
          sentinel_missing_from_dump ||
          (syslog_entries_delta && syslog_entries_delta >= ES_SYSLOG_ENTRY_DELTA_THRESHOLD) ||
          (syslog_bytes_delta && syslog_bytes_delta >= ES_SYSLOG_BYTES_DELTA_THRESHOLD) ||
          syslog_became_full_from_controlled_baseline
        payload_executed = attack[:ok] && after_sp003 && after_sp003[:syslog_burst_count] > before_sp003[:syslog_burst_count]

        evidence = {
          syslog_cleared_for_baseline: clear_syslog[:ok],
          sentinel_command_sent: sentinel[:ok],
          sentinel_hk_observed: sentinel_observed[:matched],
          sentinel_token: sentinel_token,
          es_hk_route_added: route_es[:ok],
          old_syslog_dump_removed: remove_syslog_dump[:ok],
          syslog_dump_written: write_syslog[:ok],
          syslog_dump_read: syslog_dump[:ok],
          syslog_dump_pressure_observed: syslog_dump_pressure_observed,
          syslog_dump_pressure_dominates: syslog_dump_pressure_dominates,
          syslog_dump_pressure_ratio: syslog_dump_pressure_ratio,
          syslog_dump_sp003_pressure_entries: syslog_dump[:sp003_pressure_entries],
          syslog_dump_sp003_sentinel_entries: syslog_dump[:sp003_sentinel_entries],
          sentinel_missing_from_dump: sentinel_missing_from_dump,
          syslog_dump_path: SYSLOG_DUMP_HOST_PATH,
          syslog_dump_note: syslog_dump[:ok] ? 'CFE_ES_WRITE_SYSLOG dump was readable by the verifier' : 'CFE_ES_WRITE_SYSLOG dump was not readable; collect sc01-nos-fsw docker logs as external syslog evidence',
          command_sent: attack[:ok],
          payload_executed: payload_executed,
          sp003_hk_recovered: observed[:matched],
          es_syslog_pressure_observed: syslog_pressure_observed,
          es_syslog_entries_delta: syslog_entries_delta,
          es_syslog_entry_delta_threshold: ES_SYSLOG_ENTRY_DELTA_THRESHOLD,
          es_syslog_bytes_delta: syslog_bytes_delta,
          es_syslog_bytes_delta_threshold: ES_SYSLOG_BYTES_DELTA_THRESHOLD,
          es_syslog_became_full_from_controlled_baseline: syslog_became_full_from_controlled_baseline,
          before_es_syslog_fill_ratio: before_syslog_fill_ratio,
          es_syslog_fill_ratio: syslog_fill_ratio,
          es_syslog_mode: after_es && after_es[:syslog_mode],
          es_syslog_size: after_es && after_es[:syslog_size]
        }
        verdict =
          if route_es[:ok] && clear_syslog[:ok] && sentinel[:ok] && payload_executed && syslog_pressure_observed
            'attack_success'
          elsif route_es[:ok] && clear_syslog[:ok] && sentinel[:ok] && payload_executed
            'inconclusive_no_syslog_availability_impact'
          elsif !route_es[:ok]
            'inconclusive_es_hk_route_not_available'
          elsif !clear_syslog[:ok]
            'inconclusive_syslog_baseline_not_controlled'
          elsif !sentinel[:ok]
            'inconclusive_syslog_sentinel_not_written'
          else
            'inconclusive_payload_not_confirmed'
          end
        verdict_score(verdict == 'attack_success' ? 'PASS' : 'FAIL', verdict, evidence,
                      before: { sp003: before_sp003, es: before_es }, after: { sp003: after_sp003, es: after_es },
                      wait: observed, route_es: route_es, remove_syslog_dump: remove_syslog_dump,
                      clear_syslog: clear_syslog, sentinel: sentinel, sentinel_observed: sentinel_observed,
                      write_syslog: write_syslog, syslog_dump: syslog_dump, attack: attack)
      end
    },
    {
      profile_id: 'sp003_self_restart_api',
      name: 'self_restart_api',
      risk: 'safe',
      target: 'SP003/CFE_ES',
      category: 'app_restart_pressure',
      run: lambda do
        before = read_sp003_stale_ok
        attack = sp003_run_profile(PROFILE_IDS[:self_restart_api])
        sleep(1.5)
        fresh = wait_sp003_fresh(before, 10.0)
        after = fresh[:state]
        evidence = {
          command_sent: attack[:ok],
          app_recovered: fresh[:matched],
          boot_count_increased: after && after[:boot_count] > before[:boot_count],
          restart_api_counter_increased: after && after[:restart_api_count] > before[:restart_api_count]
        }
        verdict = evidence_all?(evidence) ? 'attack_success' : 'inconclusive_no_cfs_observation'
        verdict_score(verdict == 'attack_success' ? 'PASS' : 'FAIL', verdict, evidence, before: before, after: after, attack: attack)
      end
    },
    {
      profile_id: 'sp003_restart_fm_api',
      name: 'restart_fm_api',
      risk: 'safe',
      target: 'FM/CFE_ES',
      category: 'fm_app_lifecycle_abuse',
      run: lambda do
        run_fm_restart_or_reload_lifecycle(PROFILE_IDS[:restart_target_api], :restart_api_count, 'restart')
      end
    },
    {
      profile_id: 'sp003_reload_fm_api',
      name: 'reload_fm_api',
      risk: 'safe',
      target: 'FM/CFE_ES',
      category: 'fm_app_lifecycle_abuse',
      run: lambda do
        run_fm_restart_or_reload_lifecycle(PROFILE_IDS[:reload_target_api], :reload_api_count, 'reload', FM_APP_FILE)
      end
    },
    {
      profile_id: 'sp003_self_exit_error',
      name: 'self_exit_error',
      risk: 'safe',
      target: 'SP003/CFE_ES',
      category: 'app_exit_pressure',
      run: lambda do
        before = read_sp003_stale_ok
        attack = sp003_run_profile(PROFILE_IDS[:self_exit_error])
        sleep(1.5)
        post_exit_probe = read_sp003_stale_ok rescue before
        app_stopped = !sp003_alive?(post_exit_probe, 4.0)
        recovery = sp003_start
        after_recovery = recovery[:state]
        evidence = {
          command_sent: attack[:ok],
          app_stopped_or_hk_stale_after_exit: app_stopped,
          app_recovered_after_start: recovery[:ok],
          self_exit_counter_increased: after_recovery && after_recovery[:self_exit_count] > before[:self_exit_count],
          boot_count_increased: after_recovery && after_recovery[:boot_count] > before[:boot_count]
        }
        verdict = evidence_all?(evidence) ? 'attack_success' : 'inconclusive_no_cfs_observation'
        verdict_score(verdict == 'attack_success' ? 'PASS' : 'FAIL', verdict, evidence,
                      before: before, after_exit: post_exit_probe, recovery: recovery, after: after_recovery, attack: attack)
      end
    },
    {
      profile_id: 'sp003_restart_core_es_denied',
      name: 'restart_core_es_denied',
      risk: 'safe',
      target: 'CFE_ES',
      category: 'es_api_defense',
      run: lambda do
        before = read_sp003_stale_ok
        attack = sp003_run_profile(PROFILE_IDS[:restart_target_api], [1], 'CFE_ES')
        fresh = wait_sp003_fresh(before, 6.0)
        after = fresh[:state]
        evidence = {
          command_sent: attack[:ok],
          hk_recovered: fresh[:matched],
          restart_api_counter_increased: after && after[:restart_api_count] > before[:restart_api_count],
          es_restart_core_rejected: after && after[:last_status] != 0
        }
        verdict = evidence_all?(evidence) ? 'defended' : 'inconclusive_no_cfs_observation'
        verdict_score(verdict == 'defended' ? 'FAIL' : 'ERROR', verdict, evidence,
                      defense_stage: 'CFE_ES_RestartApp core-app validation', before: before, after: after, attack: attack)
      end
    },
    {
      profile_id: 'sp003_restart_missing_app_denied',
      name: 'restart_missing_app_denied',
      risk: 'safe',
      target: 'CFE_ES',
      category: 'es_api_defense',
      run: lambda do
        before = read_sp003_stale_ok
        attack = sp003_run_profile(PROFILE_IDS[:restart_target_api], [1], 'SP003_DOES_NOT_EXIST')
        fresh = wait_sp003_fresh(before, 6.0)
        after = fresh[:state]
        evidence = {
          command_sent: attack[:ok],
          hk_recovered: fresh[:matched],
          missing_app_rejected: after && after[:last_status] != 0,
          app_still_alive: fresh[:matched]
        }
        verdict = evidence_all?(evidence) ? 'defended' : 'inconclusive_no_cfs_observation'
        verdict_score(verdict == 'defended' ? 'FAIL' : 'ERROR', verdict, evidence,
                      defense_stage: 'CFE_ES_GetAppIDByName/CFE_ES_RestartApp validation', before: before, after: after, attack: attack)
      end
    },
    {
      profile_id: 'sp003_reload_self_api',
      name: 'reload_self_api',
      risk: 'hazardous',
      target: 'SP003/CFE_ES',
      category: 'app_reload_pressure',
      run: lambda do
        before = read_sp003_stale_ok
        attack = sp003_run_profile(PROFILE_IDS[:reload_target_api], [], 'SP003', APP_FILE)
        sleep(1.5)
        fresh = wait_sp003_fresh(before, 12.0)
        after = fresh[:state]
        evidence = {
          command_sent: attack[:ok],
          app_recovered: fresh[:matched],
          reload_api_counter_increased: after && after[:reload_api_count] > before[:reload_api_count],
          boot_count_increased: after && after[:boot_count] > before[:boot_count]
        }
        verdict = evidence_all?(evidence) ? 'attack_success' : 'inconclusive_no_cfs_observation'
        verdict_score(verdict == 'attack_success' ? 'PASS' : 'FAIL', verdict, evidence, before: before, after: after, attack: attack)
      end
    },
    {
      profile_id: 'sp003_delete_self_api',
      name: 'delete_self_api',
      risk: 'hazardous',
      target: 'SP003/CFE_ES',
      category: 'app_delete_pressure',
      run: lambda do
        before = read_sp003_stale_ok
        before_es = read_es
        attack = sp003_run_profile(PROFILE_IDS[:delete_target_api], [], 'SP003')
        sleep(1.5)
        post_delete_probe = read_sp003_stale_ok rescue before
        app_stopped = !sp003_alive?(post_delete_probe, 4.0)
        after_es = read_es
        recovery = sp003_start
        after_recovery = recovery[:state]
        evidence = {
          command_sent: attack[:ok],
          app_stopped_or_hk_stale_after_delete: app_stopped,
          app_recovered_after_start: recovery[:ok],
          delete_api_counter_increased: after_recovery && after_recovery[:delete_api_count] > before[:delete_api_count],
          es_external_app_count_not_increased_during_delete: after_es[:registered_external_apps] <= before_es[:registered_external_apps]
        }
        verdict = evidence_all?(evidence) ? 'attack_success' : 'inconclusive_no_cfs_observation'
        verdict_score(verdict == 'attack_success' ? 'PASS' : 'FAIL', verdict, evidence,
                      before: { sp003: before, es: before_es }, after_delete: post_delete_probe, after_es: after_es,
                      recovery: recovery, after: after_recovery, attack: attack)
      end
    },
    {
      profile_id: 'sp003_delete_fm_then_restore',
      name: 'delete_fm_then_restore',
      risk: 'hazardous',
      target: 'FM/CFE_ES',
      category: 'fm_app_lifecycle_abuse',
      run: lambda do
        run_fm_delete_then_restore_lifecycle
      end
    },
    {
      profile_id: 'sp003_startup_exit_fault_once',
      name: 'startup_exit_fault_once',
      risk: 'hazardous',
      target: 'SP003/CFE_ES',
      category: 'startup_fault_loop',
      run: lambda do
        start = sp003_start
        before = start[:state] || read_sp003_stale_ok
        arm = sp003_run_profile(PROFILE_IDS[:arm_startup_fault_loop], [1, STARTUP_FAULT[:exit_error]])
        armed = wait_sp003_observation(before, 5.0) do |state|
          state && state[:startup_fault_remaining] == 1 && state[:startup_fault_mode] == STARTUP_FAULT[:exit_error]
        end
        restart_cmd = cmd_first(RESTART_APP_CANDIDATES)
        # CFE_ES_RestartApp is asynchronous; give the restarted app enough time to boot, consume the armed startup fault, and exit.
        sleep(8.0)
        post_fault_probe = read_sp003_stale_ok rescue (armed[:state] || before)
        app_stopped_after_fault = !sp003_alive?(post_fault_probe, 4.0)
        recovery = sp003_start
        after = recovery[:state]
        evidence = {
          app_started_before_profile: start[:ok],
          arm_command_sent: arm[:ok],
          startup_fault_armed: armed[:matched],
          restart_command_sent: restart_cmd[:ok],
          app_stopped_after_startup_fault: app_stopped_after_fault,
          recovered_after_countdown: recovery[:ok],
          self_exit_counter_increased: after && after[:self_exit_count] > before[:self_exit_count],
          startup_fault_disarmed: after && after[:startup_fault_remaining] == 0
        }
        verdict = evidence_all?(evidence) ? 'attack_success' : 'inconclusive_no_cfs_observation'
        verdict_score(verdict == 'attack_success' ? 'PASS' : 'FAIL', verdict, evidence,
                      before: before, armed: armed[:state], restart_fault: { command: restart_cmd, post_fault: post_fault_probe }, recovery: recovery, after: after, attack: arm)
      end
    },
    {
      profile_id: 'sp003_segfault_self',
      name: 'segfault_self',
      risk: 'hazardous',
      target: 'SP003/core-cpu1',
      category: 'process_fault',
      run: lambda do
        start = sp003_start
        before = start[:state] || read_sp003_stale_ok
        before_es = read_es
        attack = sp003_run_profile(PROFILE_IDS[:segfault])
        sleep(5.0)
        after_probe = wait_sp003_fresh(before, 3.0)
        recovery = sp003_start
        after_recovery = recovery[:state]
        after_es = read_es rescue nil
        required = {
          command_sent: attack[:ok],
          app_recovered_or_fsw_still_responding: recovery[:ok] || !after_es.nil?,
          crash_counter_increased_after_recovery: after_recovery && after_recovery[:crash_request_count] > before[:crash_request_count],
          es_evidence_available: !after_es.nil?
        }
        evidence = required.merge(app_hk_interrupted: !after_probe[:matched])
        verdict = evidence_all?(required) ? 'attack_success' : 'inconclusive_no_cfs_observation'
        verdict_score(verdict == 'attack_success' ? 'PASS' : 'FAIL', verdict, evidence,
                      before: { sp003: before, es: before_es }, start: start, after_probe: after_probe[:state], recovery: recovery, after: { sp003: after_recovery, es: after_es }, attack: attack)
      end
    },
    {
      profile_id: 'sp003_abort_self',
      name: 'abort_self',
      risk: 'hazardous',
      target: 'SP003/core-cpu1',
      category: 'process_fault',
      run: lambda do
        start = sp003_start
        before = start[:state] || read_sp003_stale_ok
        before_es = read_es
        attack = sp003_run_profile(PROFILE_IDS[:abort])
        sleep(5.0)
        after_probe = wait_sp003_fresh(before, 3.0)
        recovery = sp003_start
        after_recovery = recovery[:state]
        after_es = read_es rescue nil
        required = {
          command_sent: attack[:ok],
          app_recovered_or_fsw_still_responding: recovery[:ok] || !after_es.nil?,
          abort_counter_increased_after_recovery: after_recovery && after_recovery[:abort_request_count] > before[:abort_request_count],
          es_evidence_available: !after_es.nil?
        }
        evidence = required.merge(app_hk_interrupted: !after_probe[:matched])
        verdict = evidence_all?(required) ? 'attack_success' : 'inconclusive_no_cfs_observation'
        verdict_score(verdict == 'attack_success' ? 'PASS' : 'FAIL', verdict, evidence,
                      before: { sp003: before, es: before_es }, start: start, after_probe: after_probe[:state], recovery: recovery, after: { sp003: after_recovery, es: after_es }, attack: attack)
      end
    }
  ]
end

def select_profiles(profiles)
  unless %w[safe hazardous all].include?(MODE)
    raise "Invalid SP003_MODE=#{MODE.inspect}; expected safe, hazardous, or all"
  end

  if %w[hazardous all].include?(MODE)
    confirmation = ENV['SP003_CONFIRM_HAZARD'] || ENV['SP003_ALLOW_HAZARDOUS']
    raise 'Hazardous SP003 profiles require SP003_CONFIRM_HAZARD=YES' unless confirmation == 'YES'
  end

  selected = case MODE
             when 'safe'
               profiles.select { |profile| profile[:risk] == 'safe' }
             when 'hazardous'
               profiles.select { |profile| profile[:risk] == 'hazardous' }
             else
               profiles
             end

  filter = ENV['SP003_PROFILES']
  return selected if filter.nil? || filter.strip.empty?

  wanted = filter.split(',').map { |item| item.strip.downcase }.reject(&:empty?)
  selected.select { |profile| wanted.include?(profile[:name].downcase) || wanted.include?(profile[:profile_id].to_s.downcase) }
end

def run_profile(profile)
  t0 = Time.now.utc.iso8601
  base = {
    scenario: SCENARIO_ID,
    profile_id: profile[:profile_id],
    name: profile[:name],
    risk: profile[:risk],
    target: profile[:target],
    category: profile[:category],
    started_at: t0
  }

  result = profile[:run].call
  base.merge(result).merge(finished_at: Time.now.utc.iso8601)
rescue SkipProfile => skip
  base.merge(
    status: 'SKIP',
    verdict: 'skipped',
    attack_success: false,
    skip_reason: skip.reason,
    evidence: { skipped: true, reason: skip.reason },
    finished_at: Time.now.utc.iso8601
  )
rescue Exception => error
  begin
    disarm_startup_fault
    sp003_start
  rescue Exception
    nil
  end
  base.merge(
    status: 'ERROR',
    verdict: 'profile_bug',
    attack_success: false,
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace ? error.backtrace.first(8) : [],
    finished_at: Time.now.utc.iso8601
  )
end

def recovery_check
  es_noop = cmd_first(ES_NOOP_CANDIDATES)
  start = sp003_start
  before = start[:state]
  fresh = wait_sp003_fresh(before, 6.0)
  es = read_es rescue nil
  ok = es_noop[:ok] && start[:ok] && fresh[:matched] && !es.nil?
  {
    status: ok ? 'PASS' : 'FAIL',
    es_noop: es_noop,
    sp003_start: start,
    sp003_hk_fresh: fresh[:matched],
    sp003_hk: fresh[:state],
    es_hk: es
  }
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
  lines << "- Errors: #{summary[:error_count]}"
  lines << "- Recovery: `#{summary[:recovery][:status]}`"
  lines << "- Report directory: `#{report_dir}`"
  lines << ""
  lines << "## Attack Description"
  ATTACK_DESCRIPTION.each { |key, value| lines << "- #{key}: #{value}" }
  lines << ""
  lines << "## Profiles"
  scores.each do |score|
    stage = score[:defense_stage] ? " / #{score[:defense_stage]}" : ''
    lines << "- #{score[:profile_id]}: #{score[:status]} (#{score[:verdict]}#{stage}) - #{score[:target]} - #{score[:category]}"
  end
  File.write(File.join(report_dir, 'summary.md'), lines.join("\n"))
end

def main
  FileUtils.mkdir_p(REPORT_ROOT)
  write_json(File.join(REPORT_ROOT, 'attack_description.json'), ATTACK_DESCRIPTION)

  require_sp003_dictionary!
  profiles = select_profiles(make_profiles)
  raise 'No SP003 profiles selected' if profiles.empty?

  route_result = {
    sp003: ensure_sp003_telemetry_route,
    fm: ensure_fm_telemetry_route,
    es: ensure_cfs_telemetry_route(ES_HK_MID, 16),
    es_one_app: ensure_cfs_telemetry_route(ES_ONE_APP_MID, 16),
    evs: ensure_cfs_telemetry_route(EVS_HK_MID, 16),
    evs_event: ensure_cfs_telemetry_route(EVS_EVENT_MID, 64)
  }
  start_result = sp003_start
  raise "Unable to start SP003 app: #{start_result.inspect}" unless start_result[:ok]
  clear_persistent_state
  disarm_startup_fault

  scores = []
  profiles.each_with_index do |profile, index|
    puts "#{SCENARIO_ID}: #{index + 1}/#{profiles.length} #{profile[:name]}"
    score = run_profile(profile)
    scores << score
    write_profile_score(REPORT_ROOT, score)
  end

  recovery = recovery_check
  stop_result = ENV.fetch('SP003_STOP_APP_AFTER', '0') == '1' ? sp003_stop : { ok: true, skipped: true }

  pass_count = scores.count { |score| score[:status] == 'PASS' }
  fail_count = scores.count { |score| score[:status] == 'FAIL' }
  error_count = scores.count { |score| score[:status] == 'ERROR' }
  defended_count = scores.count { |score| score[:verdict] == 'defended' }
  inconclusive_count = scores.count { |score| score[:verdict].to_s.start_with?('inconclusive_') }
  verdict_counts = scores.each_with_object(Hash.new(0)) { |score, counts| counts[score[:verdict] || 'error'] += 1 }
  total = scores.length

  summary = {
    scenario: SCENARIO_ID,
    name: SCENARIO_NAME,
    mode: MODE,
    report_dir: REPORT_ROOT,
    attack_description: ATTACK_DESCRIPTION,
    total: total,
    pass_count: pass_count,
    fail_count: fail_count,
    error_count: error_count,
    defended_count: defended_count,
    inconclusive_count: inconclusive_count,
    verdict_counts: verdict_counts,
    pass_rate: total.zero? ? 0.0 : pass_count.to_f / total,
    status: (pass_count.positive? && error_count.zero? && recovery[:status] == 'PASS') ? 'PASS' : 'FAIL',
    recovery: recovery,
    telemetry_route: route_result,
    start_app: start_result,
    stop_app: stop_result,
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
  puts ""
  scores.each do |score|
    stage = score[:defense_stage] ? " / #{score[:defense_stage]}" : ''
    puts "#{score[:profile_id]}: #{score[:status]} (#{score[:verdict]}#{stage})"
  end

  exit(summary[:status] == 'PASS' ? 0 : 1)
rescue StandardError => error
  failure = {
    scenario: SCENARIO_ID,
    name: SCENARIO_NAME,
    status: 'FAIL',
    report_dir: REPORT_ROOT,
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace ? error.backtrace.first(10) : [],
    generated_at: Time.now.utc.iso8601
  }
  begin
    FileUtils.mkdir_p(REPORT_ROOT)
    write_json(File.join(REPORT_ROOT, 'summary.json'), failure)
  rescue StandardError
    nil
  end
  puts "#{SCENARIO_ID} #{SCENARIO_NAME}: FAIL"
  puts "Error: #{error.class}: #{error.message}"
  puts "Report: #{REPORT_ROOT}"
  exit 3
end

main
