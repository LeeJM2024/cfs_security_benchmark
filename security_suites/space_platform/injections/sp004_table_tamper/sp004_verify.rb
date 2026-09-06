require 'json'
require 'fileutils'
require 'socket'
require 'time'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

SCENARIO_ID = 'SP004'
SCENARIO_NAME = 'Table and configuration tampering'
REPORT_ROOT = ENV.fetch('SP004_REPORT_DIR', "/tmp/sp004_table_tamper_results/#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}")
CI_HOST = ENV.fetch('SP004_CI_HOST', 'sc01-nos-fsw')
CI_PORT = ENV.fetch('SP004_CI_PORT', '5012').to_i
HOST_CF_DIR = ENV.fetch('SP004_HOST_CF_DIR', '/home/leejm/nos3/fsw/build/exe/cpu1/cf')
SELECTED_PROFILE_IDS = ENV.fetch('SP004_ONLY', '').split(',').map(&:strip).reject(&:empty?)

APP_NAME = 'SP004'
APP_ENTRY = 'SP004_AppMain'
APP_FILE = '/cf/sp004_tbl_tamper.so'
APP_HOST_PATH = File.join(HOST_CF_DIR, File.basename(APP_FILE))
FM_BAD_TBL = '/cf/sp004_fm_bad.tbl'
FM_RESTORE_TBL = '/cf/fm_monitor.tbl'
FM_DUMP_TBL = '/cf/sp004_fm_monitor_dump.tbl'
TO_CONFIG_DUMP_TBL = '/cf/to_cfg_d.tbl'
CF_CONFIG_DUMP_TBL = '/cf/cf_cfg_d.tbl'
FM_BAD_TBL_HOST_PATH = File.join(HOST_CF_DIR, File.basename(FM_BAD_TBL))
FM_DUMP_TBL_HOST_PATH = File.join(HOST_CF_DIR, File.basename(FM_DUMP_TBL))
TO_CONFIG_DUMP_TBL_HOST_PATH = File.join(HOST_CF_DIR, File.basename(TO_CONFIG_DUMP_TBL))
CF_CONFIG_DUMP_TBL_HOST_PATH = File.join(HOST_CF_DIR, File.basename(CF_CONFIG_DUMP_TBL))
# NOS3's OSAL build limits a single file name to 20 characters.  Keep the
# complete virtual /cf path but use a short basename so the real CFE_TBL
# background writer can create the registry dump.
TBL_REGISTRY_DUMP = '/cf/treg.dat'
TBL_REGISTRY_DUMP_HOST_PATH = File.join(HOST_CF_DIR, File.basename(TBL_REGISTRY_DUMP))

SP004_CMD_MID = 0x19F4
SP004_HK_MID = 0x09F4
SP004_REQ_HK_MID = 0x19F5
TO_LAB_CMD_MID = 0x18E8
TO_HK_MID = 0x0880
CF_HK_MID = 0x08B0
FM_FREE_SPACE_MID = 0x088E
DS_HK_MID = 0x08B8
SC_HK_MID = 0x08AA
SC_1HZ_WAKEUP_MID = 0x18AB
TBL_HK_MID = 0x0804
SCH_HK_MID = 0x0897
SCH_DIAG_MID = 0x0898
LC_HK_MID = 0x08A7
CFE_TIME_CMD_MID = 0x1805
CFE_TBL_SEND_HK_MID = 0x180C
CFE_EVS_SEND_HK_MID = 0x1809
CFE_TIME_SEND_HK_MID = 0x180D
CFE_ES_SEND_HK_MID = 0x18B5
CFE_TIME_HK_MID = 0x0805
LC_SAMPLE_AP_MID = 0x18A6
DS_CMD_MID = 0x18BB
DS_SEND_HK_MID = 0x18BC
CF_CMD_MID = 0x18B3
CF_WAKE_UP_MID = 0x18B5
SC_CMD_MID = 0x18A9
SC_SEND_HK_MID = 0x18AA
SCH_SEND_HK_MID = 0x1896
LC_SEND_HK_MID = 0x18A5
CF_SEND_HK_MID = 0x18B4
TO_SEND_HK_MID = 0x1881
EVS_EVENT_MID = 0x0808
ES_ONE_APP_MID = 0x080B
TBL_REG_MID = 0x080C

CFE_TIME_SET_TIME_CC = 7
CFE_TIME_SET_MET_CC = 8
SP004_RUN_PROFILE_CC = 2
SP004_PROFILE_TBL_LOAD = 1
SP004_PROFILE_TBL_VALIDATE_INACTIVE = 2
SP004_PROFILE_TBL_ACTIVATE = 4
SP004_PROFILE_TBL_DUMP_ACTIVE = 6
SP004_PROFILE_TBL_SEND_REGISTRY = 7
SP004_PROFILE_TBL_DUMP_REGISTRY = 8
SP004_PROFILE_TBL_ABORT_LOAD = 9
SP004_PROFILE_LOAD_VALIDATE_ACTIVATE = 20
SP004_PROFILE_LOAD_VALIDATE_ACTIVATE_DUMP = 21
SP004_PROFILE_RESTORE_VALIDATE_ACTIVATE = 30
SP004_PROFILE_RESTORE_VALIDATE_ACTIVATE_DUMP = 31
SP004_TARGET_CUSTOM = 0
SP004_TARGET_DS_FILE = 1
SP004_TARGET_DS_FILTER = 2
SP004_TARGET_SCH_SCHED = 10
SP004_TARGET_SCH_MSG = 11
SP004_TARGET_LC_WDT = 20
SP004_TARGET_LC_ADT = 21
SP004_TARGET_FM_MONITOR = 30
SP004_TARGET_CF_CONFIG = 40
SP004_TARGET_TO_CONFIG = 50
SP004_TARGET_SC_RTS001 = 60
SP004_TARGET_SC_ATS1 = 61
SP004_FLAG_USE_RESTORE_FILE = 0x0008
DS_DISABLED = 0
DS_ENABLED = 1
CF_TX_FILE_CC = 2
CF_PURGE_QUEUE_CC = 21
CF_ENABLE_ENGINE_CC = 22
CF_DISABLE_ENGINE_CC = 23
SC_NOOP_CC = 0
SC_RESET_COUNTERS_CC = 1
SC_START_ATS_CC = 2
SC_STOP_ATS_CC = 3
SC_START_RTS_CC = 4
SC_STOP_RTS_CC = 5
SC_ENABLE_RTS_CC = 7
SC_RTS001_ID = 1
SC_ATS1_ID = 1
SC_ATS_TEST_TIME = 1_000_000
SC_ATS_CMD1_TIME = SC_ATS_TEST_TIME + 30
SC_ATS_ARM_TIME = SC_ATS_CMD1_TIME - 5
LC_MISSION_WDT_EXPECTED_WPS = ENV.fetch('SP004_LC_EXPECTED_WPS', '21').to_i
LC_ATTACK_WDT_EXPECTED_WPS = 1
LC_MISSION_ADT_AP_RANGE = (25..36).to_a
LC_MISSION_ADT_EXPECTED_APS = ENV.fetch('SP004_LC_EXPECTED_APS', '12').to_i
LC_ATTACK_ADT_AP = 0
LC_STATE_NAMES = { 0 => 'ZERO_NOT_DISABLED_BY_LC_CODE', 1 => 'ACTIVE', 2 => 'PASSIVE', 3 => 'DISABLED', 4 => 'FROM_CDS' }
LC_WATCH_RESULT_NAMES = { 0 => 'FALSE', 1 => 'TRUE', 2 => 'ERROR', 3 => 'STALE' }
LC_ACTION_RESULT_NAMES = {
  0 => 'NOT_USED_PASS', 1 => 'NOT_USED_FAIL', 2 => 'NOT_USED_ERROR', 3 => 'NOT_USED_STALE',
  4 => 'ACTIVE_PASS', 5 => 'ACTIVE_FAIL', 6 => 'ACTIVE_ERROR', 7 => 'ACTIVE_STALE',
  8 => 'PASSIVE_PASS', 9 => 'PASSIVE_FAIL', 10 => 'PASSIVE_ERROR', 11 => 'PASSIVE_STALE',
  12 => 'DISABLED_PASS', 13 => 'DISABLED_FAIL', 14 => 'DISABLED_ERROR', 15 => 'DISABLED_STALE'
}

ATTACK_DESCRIPTION = {
  attack_entry: 'Benchmark-controlled malicious cFS app sends unauthorized CFE_TBL commands on the Software Bus',
  affected_components: 'cFE Table Services plus real DS/SCH/LC/FM/CF/TO/SC runtime or startup table users',
  cps_type: 'Runtime configuration/table tampering',
  security_consequence: 'A malicious onboard app can replace operational tables without ground authorization, changing storage, scheduling, limit checking, file transfer, telemetry routing, stored command, and bus network behavior',
  recovery_strategy: 'Load the original table image, validate, activate, and confirm target app telemetry returns to baseline behavior',
  nos3_cfs_injection: 'CFE_ES_START_APP loads /cf/sp004_tbl_tamper.so; raw CI_LAB packets command SP004 to spoof CFE_TBL_LOAD/VALIDATE/ACTIVATE/DUMP'
}

START_APP_CANDIDATES = [
  "CFE CFE_ES_START_APP with APPLICATION #{APP_NAME}, APPENTRYPOINT #{APP_ENTRY}, APPFILENAME #{APP_FILE}, STACKSIZE 32768, EXCEPTIONACTION 0, PRIORITY 89",
  "CFS CFE_ES_START_APP with APPLICATION #{APP_NAME}, APPENTRYPOINT #{APP_ENTRY}, APPFILENAME #{APP_FILE}, STACKSIZE 32768, EXCEPTIONACTION 0, PRIORITY 89"
]

ES_QUERY_CANDIDATES = lambda do |app_name|
  [
    "CFE CFE_ES_QUERY_ONE with APPLICATION #{app_name}",
    "CFS CFE_ES_QUERY_ONE with APPLICATION #{app_name}"
  ]
end

FM_GET_FREE_SPACE_CANDIDATES = [
  'CFS FM_GET_FREE_SPACE',
  'FM FM_GET_FREE_SPACE'
]

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

  value.to_s.strip.to_i
end

def clean_string(value)
  value.to_s.delete("\u0000").strip
end

def tlm_i(target, packet, item)
  scalar_to_i(tlm("#{target} #{packet} #{item}"))
end

def tlm_raw_i(target, packet, item)
  scalar_to_i(tlm_raw("#{target} #{packet} #{item}"))
end

def tlm_i_optional(target, packet, item)
  scalar_to_i(tlm("#{target} #{packet} #{item}"))
rescue Exception
  nil
end

def tlm_i_first(target, packet, items)
  items.each do |item|
    value = tlm_i_optional(target, packet, item)
    return value unless value.nil?
  end
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

def wait_until(timeout_seconds = 8.0, interval = 0.5)
  deadline = Time.now + timeout_seconds
  last = yield

  until last[:matched] || Time.now >= deadline
    sleep(interval)
    last = yield
  end

  last
end


def json_safe(value)
  case value
  when String
    value.encode('UTF-8', invalid: :replace, undef: :replace, replace: '?')
  when Array
    value.map { |item| json_safe(item) }
  when Hash
    value.each_with_object({}) do |(key, item), safe_hash|
      safe_hash[json_safe(key)] = json_safe(item)
    end
  else
    value
  end
end

def write_json(path, object)
  FileUtils.mkdir_p(File.dirname(path))
  File.write(path, JSON.pretty_generate(json_safe(object)) + "\n")
end

def write_profile_score(report_dir, score)
  profile_dir = File.join(report_dir, 'profiles', score[:profile_id].to_s)
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

def fixed_ascii(value, size)
  raw = value.to_s.encode('ASCII', invalid: :replace, undef: :replace, replace: '?').bytes.first(size - 1).pack('C*')
  raw << "\x00"
  raw.ljust(size, "\x00")
end

def send_udp(packet)
  UDPSocket.open do |socket|
    socket.send(packet, 0, CI_HOST, CI_PORT)
  end
  { ok: true, host: CI_HOST, port: CI_PORT, bytes: packet.bytesize, checksum_result: cfe_checksum(packet) }
rescue Exception => error
  { ok: false, host: CI_HOST, port: CI_PORT, error_class: error.class.to_s, error: error.message }
end

def raw_to_lab_add(stream_mid, buffer_limit = 16)
  payload = [stream_mid & 0xFFFFFFFF].pack('V') + [0, 0, buffer_limit & 0xFF, 0].pack('C C C C')
  send_udp(command_packet(TO_LAB_CMD_MID, 6, payload))
end

def ensure_routes
  routes = {}
  {
    tbl_hk: TBL_HK_MID,
    tbl_registry: TBL_REG_MID,
    evs_event: EVS_EVENT_MID,
    time_hk: CFE_TIME_HK_MID,
    fm_free_space: FM_FREE_SPACE_MID,
    ds_hk: DS_HK_MID,
    sc_hk: SC_HK_MID,
    sch_hk: SCH_HK_MID,
    sch_diag: SCH_DIAG_MID,
    lc_hk: LC_HK_MID,
    to_hk: TO_HK_MID,
    cf_hk: CF_HK_MID,
    es_one_app: ES_ONE_APP_MID,
    sp004_hk: SP004_HK_MID
  }.each do |name, mid|
    routes[name] = raw_to_lab_add(mid, 32)
    sleep(0.15)
  end
  routes
end

def sp004_run_profile(profile_id, target_id, opts = {})
  payload = [
    profile_id.to_i,
    opts.fetch(:flags, 0).to_i,
    target_id.to_i,
    opts.fetch(:active_table_flag, 0).to_i
  ].pack('v v v v')
  payload << [
    opts.fetch(:step_delay_ms, 400).to_i,
    opts.fetch(:arg2, 0).to_i,
    opts.fetch(:arg3, 0).to_i,
    opts.fetch(:arg4, 0).to_i
  ].pack('l< l< l< l<')
  payload << fixed_ascii(opts.fetch(:table_name, ''), 64)
  payload << fixed_ascii(opts.fetch(:load_filename, ''), 64)
  payload << fixed_ascii(opts.fetch(:restore_filename, ''), 64)
  payload << fixed_ascii(opts.fetch(:dump_filename, ''), 64)

  send_udp(command_packet(SP004_CMD_MID, SP004_RUN_PROFILE_CC, payload)).merge(
    profile_id: profile_id,
    target_id: target_id,
    options: opts
  )
end

def request_tbl_hk
  send_udp(command_packet(CFE_TBL_SEND_HK_MID, 0, ''.b))
end

def request_sp004_hk
  send_udp(command_packet(SP004_REQ_HK_MID, 0, ''.b))
end

def request_es_hk
  send_udp(command_packet(CFE_ES_SEND_HK_MID, 0, ''.b))
end

def request_time_hk
  send_udp(command_packet(CFE_TIME_SEND_HK_MID, 0, ''.b))
end

def request_lc_sample_ap(start_index = LC_ATTACK_ADT_AP, end_index = start_index, update_age = 0)
  payload = [start_index.to_i, end_index.to_i, update_age.to_i].pack('v v v')
  send_udp(command_packet(LC_SAMPLE_AP_MID, 0, payload)).merge(
    start_index: start_index,
    end_index: end_index,
    update_age: update_age,
    mid: LC_SAMPLE_AP_MID
  )
end

def request_table_owner_hk(table_name)
  mid = case table_name.to_s
        when /^DS\./
          DS_SEND_HK_MID
        when /^SCH\./
          SCH_SEND_HK_MID
        when /^SC\./
          SC_SEND_HK_MID
        when /^LC\./
          LC_SEND_HK_MID
        when /^CF\./
          CF_SEND_HK_MID
        when /^TO\./
          TO_SEND_HK_MID
        else
          nil
        end
  return { ok: false, skipped: true, reason: 'no_owner_hk_mid', table_name: table_name } if mid.nil?

  send_udp(command_packet(mid, 0, ''.b)).merge(table_name: table_name, owner_hk_mid: mid)
rescue Exception => error
  { ok: false, table_name: table_name, error_class: error.class.to_s, error: error.message }
end

def read_tbl(refresh: true)
  if refresh
    request_tbl_hk
    sleep(0.25)
  end

  {
    cmd_count: tlm_i('CFS', 'CFE_TBL_HKPACKET', 'CMDCOUNTER'),
    err_count: tlm_i('CFS', 'CFE_TBL_HKPACKET', 'ERRCOUNTER'),
    num_load_pending: tlm_i('CFS', 'CFE_TBL_HKPACKET', 'NUMLOADPENDING'),
    validation_count: tlm_i('CFS', 'CFE_TBL_HKPACKET', 'VALIDATIONCTR'),
    last_val_status: tlm_i('CFS', 'CFE_TBL_HKPACKET', 'LASTVALSTATUS'),
    success_val_count: tlm_i('CFS', 'CFE_TBL_HKPACKET', 'SUCCESSVALCTR'),
    failed_val_count: tlm_i('CFS', 'CFE_TBL_HKPACKET', 'FAILEDVALCTR'),
    last_updated_tbl: clean_string(tlm('CFS CFE_TBL_HKPACKET LASTUPDATEDTBL')),
    last_file_loaded: clean_string(tlm('CFS CFE_TBL_HKPACKET LASTFILELOADED')),
    last_file_dumped: clean_string(tlm('CFS CFE_TBL_HKPACKET LASTFILEDUMPED')),
    last_table_loaded: clean_string(tlm('CFS CFE_TBL_HKPACKET LASTTABLELOADED')),
    last_val_table_name: clean_string(tlm('CFS CFE_TBL_HKPACKET LASTVALTABLENAME'))
  }
end


def read_tbl_registry
  {
    sequence: tlm_i('CFS', 'CFE_TBL_TBLREGPACKET', 'CCSDS_SEQUENCE'),
    size: tlm_i('CFS', 'CFE_TBL_TBLREGPACKET', 'SIZE'),
    crc: tlm_i('CFS', 'CFE_TBL_TBLREGPACKET', 'CRC'),
    name: clean_string(tlm('CFS CFE_TBL_TBLREGPACKET NAME')),
    last_file_loaded: clean_string(tlm('CFS CFE_TBL_TBLREGPACKET LASTFILELOADED')),
    owner_app_name: clean_string(tlm('CFS CFE_TBL_TBLREGPACKET OWNERAPPNAME')),
    table_loaded_once: tlm_i('CFS', 'CFE_TBL_TBLREGPACKET', 'TABLELOADEDONCE'),
    load_pending: tlm_i('CFS', 'CFE_TBL_TBLREGPACKET', 'LOADPENDING'),
    dump_only: tlm_i('CFS', 'CFE_TBL_TBLREGPACKET', 'DUMPONLY')
  }
end

def read_tbl_registry_safe
  read_tbl_registry
rescue Exception => error
  { error_class: error.class.to_s, error: error.message }
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

def fm_verify_good_entries(events)
  return [] unless events.is_a?(Hash)

  events.fetch(:events, []).each_with_object([]) do |event, values|
    next unless event[:app_name] == 'FM'

    match = event[:message].to_s.match(/Free Space Table verify results: good entries =\s*(\d+)/)
    values << match[1].to_i if match
  end
end

def read_sp004_optional(refresh: true)
  return { available: false, reason: 'SP004 telemetry dictionary is not loaded' } unless telemetry_packet_exists?('CFS', 'SP004_HK_TLM')

  if refresh
    request_sp004_hk
    sleep(0.25)
  end

  {
    available: true,
    cmd_count: tlm_i('CFS', 'SP004_HK_TLM', 'COMMANDCOUNT'),
    err_count: tlm_i('CFS', 'SP004_HK_TLM', 'COMMANDERRCOUNT'),
    last_profile_id: tlm_i('CFS', 'SP004_HK_TLM', 'LASTPROFILEID'),
    last_target_id: tlm_i('CFS', 'SP004_HK_TLM', 'LASTTARGETID'),
    last_status: tlm_i('CFS', 'SP004_HK_TLM', 'LASTSTATUS'),
    tbl_load_count: tlm_i('CFS', 'SP004_HK_TLM', 'TBLLOADCOUNT'),
    tbl_validate_count: tlm_i('CFS', 'SP004_HK_TLM', 'TBLVALIDATECOUNT'),
    tbl_activate_count: tlm_i('CFS', 'SP004_HK_TLM', 'TBLACTIVATECOUNT'),
    tbl_dump_count: tlm_i('CFS', 'SP004_HK_TLM', 'TBLDUMPCOUNT'),
    restore_count: tlm_i('CFS', 'SP004_HK_TLM', 'RESTORECOUNT'),
    tx_error_count: tlm_i('CFS', 'SP004_HK_TLM', 'TXERRORCOUNT')
  }
rescue Exception => error
  { available: false, error_class: error.class.to_s, error: error.message }
end



def wait_sp004_cmd_counter_increment(before_hk, timeout = 6.0)
  before_count = before_hk.is_a?(Hash) && before_hk[:available] ? before_hk[:cmd_count].to_i : nil
  wait_until(timeout, 0.5) do
    current = read_sp004_optional
    matched = current[:available] && !before_count.nil? && current[:cmd_count].to_i > before_count
    { matched: matched, before: before_hk, current: current }
  end
end

def query_one_app(app_name)
  command = cmd_first(ES_QUERY_CANDIDATES.call(app_name))
  sleep(0.6)
  state = {
    name: clean_string(tlm('CFS CFE_ES_ONEAPPTLM APPINFO_NAME')),
    entry_point: clean_string(tlm('CFS CFE_ES_ONEAPPTLM APPINFO_ENTRYPOINT')),
    filename: clean_string(tlm('CFS CFE_ES_ONEAPPTLM APPINFO_FILENAME')),
    main_task_id: tlm_i('CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_MAINTASKID')
  }
  { ok: command[:ok] && state[:name] == app_name, command: command, state: state }
rescue Exception => error
  { ok: false, command: command, error_class: error.class.to_s, error: error.message }
end


def start_sp004
  before = query_one_app(APP_NAME)
  start = cmd_first(START_APP_CANDIDATES)
  sleep(2.0)
  after = query_one_app(APP_NAME)

  # ES one-app telemetry can be stale after a container restart, so the verifier
  # always attempts START_APP and treats an already-running app as acceptable only
  # when the post-query still reports SP004.
  { ok: after[:ok] || before[:ok], action: 'start_app_or_confirm_alive', command: start, before: before, after: after }
end

def fm_free_space_packet(timeout = 8.0)
  before_seq = tlm_i('CFS', 'FM_FREESPACEPKT', 'CCSDS_SEQUENCE') rescue nil
  command = cmd_first(FM_GET_FREE_SPACE_CANDIDATES)
  errors = []
  result = wait_until(timeout, 0.4) do
    begin
      seq = tlm_i('CFS', 'FM_FREESPACEPKT', 'CCSDS_SEQUENCE')
      fresh = before_seq.nil? || seq != before_seq
      names = (1..8).map { |idx| clean_string(tlm("CFS FM_FREESPACEPKT NAME#{idx}")) }
      free_words = (1..8).map do |idx|
        {
          index: idx,
          name: names[idx - 1],
          freespace_a: tlm_i('CFS', 'FM_FREESPACEPKT', "FREESPACE#{idx}A"),
          freespace_b: tlm_i('CFS', 'FM_FREESPACEPKT', "FREESPACE#{idx}B")
        }
      end
      { matched: fresh, sequence: seq, names: names, present_names: names.reject(&:empty?), free_words: free_words, command: command }
    rescue Exception => error
      errors << { error_class: error.class.to_s, error: error.message }
      { matched: false, command: command }
    end
  end
  result[:errors] = errors.first(5) unless errors.empty?
  result
end

def fm_present_names(packet)
  return [] unless packet.is_a?(Hash)

  Array(packet[:present_names] || packet['present_names'] || packet[:names] || packet['names']).map { |name| clean_string(name) }.reject(&:empty?)
end

def fm_report_signature_words(packet)
  return [] unless packet.is_a?(Hash)

  Array(packet[:free_words] || packet['free_words']).flat_map do |entry|
    next [] unless entry.is_a?(Hash)

    [entry[:freespace_a] || entry['freespace_a'], entry[:freespace_b] || entry['freespace_b']].map(&:to_i)
  end
end

def fm_monitor_report_has_content?(packet)
  packet.is_a?(Hash) && packet[:matched] && (!fm_present_names(packet).empty? || fm_report_signature_words(packet).any?(&:positive?))
end

def fm_monitor_report_all_zero?(packet)
  packet.is_a?(Hash) && packet[:matched] && fm_present_names(packet).empty? && fm_report_signature_words(packet).all?(&:zero?)
end

def wait_tbl_observation(before, timeout = 8.0)
  errors = []
  wait_until(timeout, 0.5) do
    begin
      state = read_tbl
      matched = state[:cmd_count].to_i > before[:cmd_count].to_i ||
                state[:validation_count].to_i > before[:validation_count].to_i ||
                state[:last_file_loaded].include?('sp004_') ||
                state[:last_file_dumped].include?('sp004_')
      { matched: matched, state: state }
    rescue Exception => error
      errors << { error_class: error.class.to_s, error: error.message }
      { matched: false }
    end
  end.merge(errors: errors.first(5))
end

def wait_for_file(path, timeout = 8.0)
  wait_until(timeout, 0.4) do
    { matched: File.exist?(path), path: path, size: File.exist?(path) ? File.size(path) : 0 }
  end
end

def file_contains?(path, needle)
  return false unless File.exist?(path)

  File.binread(path).include?(needle)
rescue Exception
  false
end

def remove_file(path)
  File.delete(path) if File.exist?(path)
  { ok: true, path: path }
rescue Exception => error
  { ok: false, path: path, error_class: error.class.to_s, error: error.message }
end

def verdict_score(status, verdict, evidence, extra = {})
  {
    status: status,
    verdict: verdict,
    attack_success: verdict.to_s.start_with?('attack_success'),
    evidence: evidence
  }.merge(extra)
end




def event_messages(events)
  return [] unless events.is_a?(Hash)

  events.fetch(:events, []).map { |event| event[:message].to_s }
end

def events_include?(events, needle)
  event_messages(events).any? { |message| message.include?(needle) }
end

def events_include_any?(events, needles)
  messages = event_messages(events)
  needles.any? do |needle|
    messages.any? { |message| message.include?(needle) }
  end
end

def event_text_matches?(events, patterns)
  event_messages(events).any? do |message|
    patterns.any? do |pattern|
      pattern.is_a?(Regexp) ? message.match?(pattern) : message.include?(pattern.to_s)
    end
  end
end

def tbl_state_value(state, key)
  return '' unless state.is_a?(Hash)

  clean_string(state.fetch(key, ''))
end

def tbl_state_mentions?(state, key, table_name)
  tbl_state_value(state, key).include?(table_name.to_s)
end

def table_event_patterns(table_name, kind)
  escaped = Regexp.escape(table_name)
  case kind
  when :validated
    [/validation successful for Inactive '#{escaped}'/i, /Validation of Inactive '#{escaped}' successful/i, /#{escaped}.*validation successful/i]
  when :activated
    ["Successfully Updated '#{table_name}'", /Successfully Updated '#{escaped}'/i, /#{escaped}.*Successfully Updated/i]
  when :missing
    ["Unable to locate '#{table_name}' in Table Registry"]
  else
    []
  end
end

def host_cf_path(cf_path)
  File.join(HOST_CF_DIR, File.basename(cf_path))
end

def cf_file_snapshot(patterns)
  Array(patterns).flat_map do |pattern|
    Dir.glob(File.join(HOST_CF_DIR, pattern)).sort.map do |path|
      stat = File.stat(path)
      {
        path: path,
        basename: File.basename(path),
        size: stat.size,
        mtime: stat.mtime.to_f,
        mtime_utc: stat.mtime.utc.iso8601(6)
      }
    end
  end
rescue Exception => error
  [{ error_class: error.class.to_s, error: error.message }]
end

def cf_snapshot_index(snapshot)
  Array(snapshot).each_with_object({}) do |entry, index|
    next unless entry.is_a?(Hash) && entry[:path]

    index[entry[:path]] = entry
  end
end

def cf_file_activity(patterns, before_snapshot)
  before = cf_snapshot_index(before_snapshot)
  after = cf_file_snapshot(patterns)
  new_files = []
  changed_files = []

  after.each do |entry|
    next unless entry.is_a?(Hash) && entry[:path]

    previous = before[entry[:path]]
    if previous.nil?
      new_files << entry
    elsif entry[:size].to_i != previous[:size].to_i || entry[:mtime].to_f > previous[:mtime].to_f + 0.000001
      changed_files << entry.merge(previous_size: previous[:size], previous_mtime_utc: previous[:mtime_utc])
    end
  end

  {
    matched: !new_files.empty? || !changed_files.empty?,
    patterns: patterns,
    before: before_snapshot,
    after: after,
    new_files: new_files,
    changed_files: changed_files
  }
end

def wait_for_cf_file_activity(patterns, before_snapshot, timeout = 10.0, interval = 0.5)
  deadline = Time.now + timeout
  last = nil

  until Time.now >= deadline
    last = cf_file_activity(patterns, before_snapshot)
    return last.merge(reason: last[:new_files].empty? ? 'existing_file_changed' : 'new_file_created') if last[:matched]

    sleep(interval)
  end

  (last || cf_file_activity(patterns, before_snapshot)).merge(reason: 'timeout_no_file_activity')
end

def read_ds_hk(refresh = true)
  request_table_owner_hk('DS.FILTER_TBL') if refresh
  sleep(0.25) if refresh

  {
    received_count: tlm_i('CFS', 'DS_HKPACKET', 'RECEIVED_COUNT'),
    packet_time: tlm('CFS DS_HKPACKET PACKET_TIMESECONDS'),
    dest_tbl_load_counter: tlm_i('CFS', 'DS_HKPACKET', 'DESTTBLLOADCOUNTER'),
    filter_tbl_load_counter: tlm_i('CFS', 'DS_HKPACKET', 'FILTERTBLLOADCOUNTER'),
    app_enable_state: tlm_i('CFS', 'DS_HKPACKET', 'APPENABLESTATE'),
    file_write_counter: tlm_i('CFS', 'DS_HKPACKET', 'FILEWRITECOUNTER'),
    file_write_err_counter: tlm_i('CFS', 'DS_HKPACKET', 'FILEWRITEERRCOUNTER'),
    disabled_pkt_counter: tlm_i('CFS', 'DS_HKPACKET', 'DISABLEDPKTCOUNTER'),
    ignored_pkt_counter: tlm_i('CFS', 'DS_HKPACKET', 'IGNOREDPKTCOUNTER'),
    filtered_pkt_counter: tlm_i('CFS', 'DS_HKPACKET', 'FILTEREDPKTCOUNTER'),
    passed_pkt_counter: tlm_i('CFS', 'DS_HKPACKET', 'PASSEDPKTCOUNTER')
  }
rescue Exception => error
  { error_class: error.class.to_s, error: error.message }
end

def sc_tlm_target
  @sc_tlm_target ||= ['CFS', 'SC'].find { |target| telemetry_packet_exists?(target, 'SC_HKTLM') } || 'CFS'
end

def read_sc_hk(refresh = true)
  request_table_owner_hk('SC.RTS_TBL001') if refresh
  sleep(0.25) if refresh

  target = sc_tlm_target
  {
    target: target,
    received_count: tlm_i_optional(target, 'SC_HKTLM', 'RECEIVED_COUNT'),
    cmd_counter: tlm_i(target, 'SC_HKTLM', 'CMDCTR'),
    cmd_err_counter: tlm_i(target, 'SC_HKTLM', 'CMDERRCTR'),
    num_rts_active: tlm_i(target, 'SC_HKTLM', 'NUMRTSACTIVE'),
    rts_number: tlm_i(target, 'SC_HKTLM', 'RTSNUMBER'),
    rts_active_count: tlm_i(target, 'SC_HKTLM', 'RTSACTIVECTR'),
    rts_active_err_count: tlm_i(target, 'SC_HKTLM', 'RTSACTIVEERRCTR'),
    rts_cmd_count: tlm_i(target, 'SC_HKTLM', 'RTSCMDCTR'),
    rts_cmd_err_count: tlm_i(target, 'SC_HKTLM', 'RTSCMDERRCTR'),
    ats_number: tlm_i_optional(target, 'SC_HKTLM', 'ATSNUMBER'),
    atp_state: tlm_i_optional(target, 'SC_HKTLM', 'ATPSTATE'),
    ats_cmd_count: tlm_i_optional(target, 'SC_HKTLM', 'ATSCMDCTR'),
    ats_cmd_err_count: tlm_i_optional(target, 'SC_HKTLM', 'ATSCMDERRCTR'),
    atp_cmd_number: tlm_i_optional(target, 'SC_HKTLM', 'ATPCMDNUMBER'),
    rts1_executing: tlm_i_optional(target, 'SC_HKTLM', 'RTS1_EXECUTING')
  }
rescue Exception => error
  { error_class: error.class.to_s, error: error.message }
end

def read_time_hk(refresh = true)
  if refresh
    request_time_hk
    sleep(0.25)
  end

  {
    received_count: tlm_i_optional('CFS', 'CFE_TIME_HKPACKET', 'RECEIVED_COUNT'),
    packet_time_seconds: tlm_i_optional('CFS', 'CFE_TIME_HKPACKET', 'CCSDS_SECONDS'),
    packet_time_subsecs: tlm_i_optional('CFS', 'CFE_TIME_HKPACKET', 'CCSDS_SUBSECS'),
    cmd_counter: tlm_i('CFS', 'CFE_TIME_HKPACKET', 'CMDCOUNTER'),
    err_counter: tlm_i('CFS', 'CFE_TIME_HKPACKET', 'ERRCOUNTER'),
    seconds_met: tlm_i_optional('CFS', 'CFE_TIME_HKPACKET', 'SECONDSMET'),
    subsecs_met: tlm_i_optional('CFS', 'CFE_TIME_HKPACKET', 'SUBSECSMET'),
    seconds_stcf: tlm_i_optional('CFS', 'CFE_TIME_HKPACKET', 'SECONDSSTCF'),
    subsecs_stcf: tlm_i_optional('CFS', 'CFE_TIME_HKPACKET', 'SUBSECSSTCF')
  }
rescue Exception => error
  { error_class: error.class.to_s, error: error.message }
end

def set_cfe_time(seconds, microseconds = 0)
  payload = [seconds.to_i & 0xFFFFFFFF, microseconds.to_i & 0xFFFFFFFF].pack('V V')
  send_udp(command_packet(CFE_TIME_CMD_MID, CFE_TIME_SET_TIME_CC, payload)).merge(
    seconds: seconds.to_i,
    microseconds: microseconds.to_i
  )
end

def set_cfe_met(seconds, microseconds = 0)
  payload = [seconds.to_i & 0xFFFFFFFF, microseconds.to_i & 0xFFFFFFFF].pack('V V')
  send_udp(command_packet(CFE_TIME_CMD_MID, CFE_TIME_SET_MET_CC, payload)).merge(
    seconds: seconds.to_i,
    microseconds: microseconds.to_i
  )
end

def restore_cfe_met_from_snapshot(snapshot, started_wall)
  unless snapshot.is_a?(Hash) && snapshot[:seconds_met]
    return { ok: false, skipped: true, reason: 'time_snapshot_missing_met', snapshot: snapshot }
  end

  restored_seconds = snapshot[:seconds_met].to_i + [(Time.now - started_wall).ceil, 1].max
  command = set_cfe_met(restored_seconds, 0)
  restore_wait = wait_until(6.0, 0.4) do
    current = read_time_hk(true)
    {
      matched: current.is_a?(Hash) && !current[:error_class] && current[:seconds_met].to_i >= restored_seconds,
      current: current
    }
  end
  after = restore_wait[:current] || read_time_hk(true)
  command.merge(restored_seconds: restored_seconds, restore_wait: restore_wait, after_restore_hk: after)
end

def restore_cfe_time_from_snapshot(snapshot, started_wall)
  unless snapshot.is_a?(Hash) && snapshot[:packet_time_seconds]
    return { ok: false, skipped: true, reason: 'time_snapshot_missing_packet_time', snapshot: snapshot }
  end

  restored_seconds = snapshot[:packet_time_seconds].to_i + [(Time.now - started_wall).ceil, 1].max
  command = set_cfe_time(restored_seconds, 0)
  sleep(0.5)
  after = read_time_hk(true)
  command.merge(restored_seconds: restored_seconds, after_restore_hk: after)
end

def sc_noop
  send_udp(command_packet(SC_CMD_MID, SC_NOOP_CC, ''.b))
end

def sc_reset_counters
  send_udp(command_packet(SC_CMD_MID, SC_RESET_COUNTERS_CC, ''.b))
end

def set_ds_app_state(state)
  payload = [state.to_i, 0].pack('v v')
  send_udp(command_packet(DS_CMD_MID, 2, payload)).merge(requested_state: state)
end

def sc_enable_rts(rts_id = SC_RTS001_ID)
  payload = [rts_id.to_i, 0].pack('v v')
  send_udp(command_packet(SC_CMD_MID, SC_ENABLE_RTS_CC, payload)).merge(rts_id: rts_id)
end

def sc_start_rts(rts_id = SC_RTS001_ID)
  payload = [rts_id.to_i, 0].pack('v v')
  send_udp(command_packet(SC_CMD_MID, SC_START_RTS_CC, payload)).merge(rts_id: rts_id)
end

def sc_stop_rts(rts_id = SC_RTS001_ID)
  payload = [rts_id.to_i, 0].pack('v v')
  send_udp(command_packet(SC_CMD_MID, SC_STOP_RTS_CC, payload)).merge(rts_id: rts_id)
end

def sc_start_ats(ats_id = SC_ATS1_ID)
  payload = [ats_id.to_i, 0].pack('v v')
  send_udp(command_packet(SC_CMD_MID, SC_START_ATS_CC, payload)).merge(ats_id: ats_id)
end

def sc_stop_ats
  send_udp(command_packet(SC_CMD_MID, SC_STOP_ATS_CC, ''.b))
end

def sc_wakeup
  packet = [SC_1HZ_WAKEUP_MID & 0xFFFF, 0xC000, 1, 0].pack('n n n n')
  send_udp(packet)
end

def current_event_sequence
  read_event_packet[:sequence]
rescue Exception
  nil
end

def collect_events_after_sequence(initial_sequence, duration_seconds = 6.0, interval = 0.15)
  deadline = Time.now + duration_seconds
  events = []
  errors = []
  last_seq = initial_sequence

  last_wakeup = Time.at(0)

  until Time.now >= deadline
    if (Time.now - last_wakeup) >= 1.0
      sc_wakeup
      last_wakeup = Time.now
    end

    begin
      event = read_event_packet
      seq = event[:sequence]
      if !seq.nil? && seq != last_seq
        events << event
        last_seq = seq
      end
    rescue Exception => error
      errors << { error_class: error.class.to_s, error: error.message } if errors.length < 5
    end
    sleep(interval)
  end

  { events: events, errors: errors, initial_sequence: initial_sequence }
end

def sc_ats1_source_first_cmd(path)
  return { ok: false, path: path, reason: 'file_missing' } unless File.exist?(path)

  text = File.read(path)
  match = text.match(/\.cmd1\.CmdHeader\s*=\s*CFE_MSG_CMD_HDR_INIT\([^,]+,[^,]+,\s*(SC_[A-Z0-9_]+_CC)/m)
  return { ok: false, path: path, reason: 'cmd1_command_code_not_found' } unless match

  { ok: true, path: path, cmd1_command: match[1] }
rescue Exception => error
  { ok: false, path: path, error_class: error.class.to_s, error: error.message }
end

def run_sc_ats1_first_command_trial(label, expect_reset, timeout = 45.0)
  started_wall = Time.now
  time_before = read_time_hk(true)
  stop_before = sc_stop_ats
  sleep(0.5)
  reset_setup = sc_reset_counters
  reset_observed = wait_until(5.0, 0.35) do
    current = read_sc_hk(true)
    {
      matched: current.is_a?(Hash) && !current[:error_class] && current[:cmd_counter].to_i <= 1,
      current: current
    }
  end
  noop_setup = 3.times.map do
    result = sc_noop
    sleep(0.25)
    result
  end
  before_ready = wait_until(5.0, 0.35) do
    current = read_sc_hk(true)
    {
      matched: current.is_a?(Hash) && !current[:error_class] && current[:cmd_counter].to_i >= 3,
      current: current
    }
  end
  before_sc = before_ready[:current] || read_sc_hk(true)
  stcf_seconds = time_before.is_a?(Hash) ? time_before[:seconds_stcf].to_i : 0
  armed_met_seconds = [SC_ATS_ARM_TIME - stcf_seconds, 0].max
  expected_cfe_time_seconds = armed_met_seconds + stcf_seconds
  arm_time_command = set_cfe_met(armed_met_seconds, 0)
  armed_time_wait = wait_until(6.0, 0.4) do
    current = read_time_hk(true)
    current_cfe_time = current.is_a?(Hash) ? current[:seconds_met].to_i + current[:seconds_stcf].to_i : 0
    {
      matched: current.is_a?(Hash) && !current[:error_class] && current_cfe_time >= expected_cfe_time_seconds,
      current: current,
      current_cfe_time_seconds: current_cfe_time
    }
  end
  armed_time = armed_time_wait[:current] || read_time_hk(true)
  pre_start_wakeup = sc_wakeup
  sleep(0.5)
  initial_event_sequence = current_event_sequence
  start_result = sc_start_ats(SC_ATS1_ID)
  events = collect_events_after_sequence(initial_event_sequence, timeout, 0.15)
  after_sc = read_sc_hk(true)
  stop_after = sc_stop_ats
  restore_time = restore_cfe_met_from_snapshot(time_before, started_wall)
  reset_event_observed = event_text_matches?(events, [/Reset counters command/i])
  ats_started_event_observed = event_text_matches?(events, [/ATS A Execution Started/i])
  noop_event_observed = event_text_matches?(events, [/No-op command/i, /Noop command/i])
  cmd_counter_delta = counter_delta(after_sc, before_sc, :cmd_counter)
  ats_cmd_delta = counter_delta(after_sc, before_sc, :ats_cmd_count)
  cmd_counter_reset_observed = before_sc.is_a?(Hash) && after_sc.is_a?(Hash) &&
                               before_sc[:cmd_counter].to_i >= 3 &&
                               after_sc[:cmd_counter].to_i < before_sc[:cmd_counter].to_i
  ats_cmd_counter_reset_observed = before_sc.is_a?(Hash) && after_sc.is_a?(Hash) &&
                                   !before_sc[:ats_cmd_count].nil? && !after_sc[:ats_cmd_count].nil? &&
                                   after_sc[:ats_cmd_count].to_i <= before_sc[:ats_cmd_count].to_i
  reset_observed_at_runtime = reset_event_observed || cmd_counter_reset_observed
  original_noop_effect_observed = ats_started_event_observed && noop_event_observed && !reset_event_observed

  {
    label: label,
    ats_id: SC_ATS1_ID,
    expected_first_command_time: SC_ATS_CMD1_TIME,
    armed_time_seconds: SC_ATS_ARM_TIME,
    armed_met_seconds: armed_met_seconds,
    expected_cfe_time_seconds: expected_cfe_time_seconds,
    stcf_seconds: stcf_seconds,
    expect_reset: expect_reset,
    time_before: time_before,
    stop_before: stop_before,
    reset_setup: reset_setup,
    reset_setup_observed: reset_observed,
    noop_setup: noop_setup,
    before_counter_ready: before_ready,
    before_sc: before_sc,
    arm_time_command: arm_time_command,
    armed_time_wait: armed_time_wait,
    armed_time: armed_time,
    pre_start_wakeup: pre_start_wakeup,
    initial_event_sequence: initial_event_sequence,
    start_result: start_result,
    events: events,
    after_sc: after_sc,
    stop_after: stop_after,
    restore_time: restore_time,
    ats_started_event_observed: ats_started_event_observed,
    noop_event_observed: noop_event_observed,
    reset_event_observed: reset_event_observed,
    cmd_counter_delta: cmd_counter_delta,
    ats_cmd_delta: ats_cmd_delta,
    cmd_counter_reset_observed: cmd_counter_reset_observed,
    ats_cmd_counter_reset_observed: ats_cmd_counter_reset_observed,
    confirmed: expect_reset ? (ats_started_event_observed && reset_observed_at_runtime) : original_noop_effect_observed
  }
end

def wait_for_ds_app_state(expected_state, timeout = 8.0, interval = 0.5)
  samples = []
  last = wait_until(timeout, interval) do
    current = read_ds_hk(true)
    samples << current if samples.length < 12
    {
      matched: current.is_a?(Hash) && !current[:error_class] && current[:app_enable_state].to_i == expected_state.to_i,
      current: current
    }
  end
  last.merge(expected_state: expected_state, samples: samples)
end

def sc_rts001_source_ds_state(path)
  return { ok: false, path: path, reason: 'file_missing' } unless File.exist?(path)

  text = File.read(path)
  match = text.match(/\.cmd1\.Payload\.EnableState\s*=\s*(0x[0-9a-fA-F]+|\d+)/)
  return { ok: false, path: path, reason: 'cmd1_enable_state_not_found' } unless match

  value = match[1].start_with?('0x', '0X') ? match[1].to_i(16) : match[1].to_i
  { ok: true, path: path, ds_cmd1_enable_state: value }
rescue Exception => error
  { ok: false, path: path, error_class: error.class.to_s, error: error.message }
end

def run_sc_rts1_ds_state_trial(label, setup_state, expected_final_state, timeout = 18.0)
  before_ds = read_ds_hk(true)
  before_sc = read_sc_hk(true)
  stop_result = sc_stop_rts(SC_RTS001_ID)
  sleep(0.5)
  setup_command = set_ds_app_state(setup_state)
  setup_observed = wait_for_ds_app_state(setup_state, 8.0, 0.5)
  enable_result = sc_enable_rts(SC_RTS001_ID)
  sleep(0.5)
  start_result = sc_start_rts(SC_RTS001_ID)
  rts_events = collect_events(2.5, 0.15)
  ds_observed = wait_for_ds_app_state(expected_final_state, timeout, 0.5)
  after_sc = read_sc_hk(true)
  after_ds = read_ds_hk(false)
  rts_active_delta = counter_delta(after_sc, before_sc, :rts_active_count)
  rts_cmd_delta = counter_delta(after_sc, before_sc, :rts_cmd_count)
  rts_activity_observed = rts_active_delta.to_i > 0 || rts_cmd_delta.to_i > 0
  rts_start_event_observed = event_text_matches?(rts_events, [/RTS Number 001 Started/i, /Start RTS #?1/i])

  {
    label: label,
    rts_id: SC_RTS001_ID,
    setup_state: setup_state,
    expected_final_state: expected_final_state,
    before_ds: before_ds,
    before_sc: before_sc,
    stop_result: stop_result,
    setup_command: setup_command,
    setup_observed: setup_observed,
    enable_result: enable_result,
    start_result: start_result,
    rts_events: rts_events,
    rts_start_event_observed: rts_start_event_observed,
    ds_observed: ds_observed,
    after_sc: after_sc,
    after_ds: after_ds,
    rts_active_delta: rts_active_delta,
    rts_cmd_delta: rts_cmd_delta,
    rts_activity_observed: rts_activity_observed,
    confirmed: setup_observed[:matched] == true && start_result[:ok] == true && ds_observed[:matched] == true
  }
end

def cf_tlm_target
  @cf_tlm_target ||= ['CF', 'CFS'].find { |target| telemetry_packet_exists?(target, 'CF_HKPACKET') } || 'CF'
end

def read_cf_hk(refresh = true)
  if refresh
    request_table_owner_hk('CF.config_table')
    sleep(0.35)
  end

  target = cf_tlm_target
  q1 = (1..7).map { |index| tlm_i_optional(target, 'CF_HKPACKET', "CH1_Q_SIZE_#{index}") }
  q2 = (1..7).map { |index| tlm_i_optional(target, 'CF_HKPACKET', "CH2_Q_SIZE_#{index}") }
  {
    target: target,
    received_count: tlm_i_optional(target, 'CF_HKPACKET', 'RECEIVED_COUNT'),
    cmd_counter: tlm_i(target, 'CF_HKPACKET', 'CMDCOUNTER'),
    err_counter: tlm_i(target, 'CF_HKPACKET', 'ERRCOUNTER'),
    ch1_sent_pdu: tlm_i(target, 'CF_HKPACKET', 'CH1_SENT_PDU'),
    ch1_sent_file_data_bytes: tlm_i(target, 'CF_HKPACKET', 'CH1_SENT_FILE_DATA_BYTES'),
    ch1_q_sizes: q1,
    ch1_pending_q_size: q1[0],
    ch1_active_q_size: q1[1],
    ch1_playback_counter: tlm_i(target, 'CF_HKPACKET', 'CH1_PLAYBACK_COUNTER'),
    ch1_poll_counter: tlm_i(target, 'CF_HKPACKET', 'CH1_POLL_COUNTER'),
    ch2_sent_pdu: tlm_i(target, 'CF_HKPACKET', 'CH2_SENT_PDU'),
    ch2_q_sizes: q2,
    ch2_pending_q_size: q2[0],
    ch2_active_q_size: q2[1],
    ch2_playback_counter: tlm_i(target, 'CF_HKPACKET', 'CH2_PLAYBACK_COUNTER'),
    ch2_poll_counter: tlm_i(target, 'CF_HKPACKET', 'CH2_POLL_COUNTER')
  }
rescue Exception => error
  { error_class: error.class.to_s, error: error.message }
end

def cf_no_args(fc)
  send_udp(command_packet(CF_CMD_MID, fc, ''.b)).merge(function_code: fc)
end

def cf_disable_engine
  cf_no_args(CF_DISABLE_ENGINE_CC)
end

def cf_enable_engine
  cf_no_args(CF_ENABLE_ENGINE_CC)
end

def cf_wakeup
  packet = [CF_WAKE_UP_MID & 0xFFFF, 0xC000, 1, 0].pack('n n n n')
  send_udp(packet)
end

def cf_purge_downlink_pending_history(chan = 0)
  payload = [chan.to_i, 2, 0, 0].pack('C C C C')
  send_udp(command_packet(CF_CMD_MID, CF_PURGE_QUEUE_CC, payload)).merge(chan: chan, purge: 'pending_and_history')
end

def cf_tx_file(src_cf_path, dst_path, chan = 0, dest_eid = 23, priority = 1, cfdp_class = 0, keep = 1)
  payload = [cfdp_class.to_i, keep.to_i, chan.to_i, priority.to_i].pack('C C C C')
  payload << [dest_eid.to_i].pack('V')
  payload << fixed_ascii(src_cf_path, 64)
  payload << fixed_ascii(dst_path, 64)
  send_udp(command_packet(CF_CMD_MID, CF_TX_FILE_CC, payload)).merge(
    src_cf_path: src_cf_path,
    dst_path: dst_path,
    chan: chan,
    dest_eid: dest_eid,
    priority: priority,
    cfdp_class: cfdp_class,
    keep: keep
  )
end

def cf_sync_config_table_with_engine_gate(label)
  before_hk = read_cf_hk(true)
  disable = cf_disable_engine
  disable_events = collect_events(1.5, 0.15)
  hk_manage = read_cf_hk(true)
  sleep(0.5)
  enable = cf_enable_engine
  enable_events = collect_events(2.5, 0.15)
  after_hk = read_cf_hk(true)
  disable_seen = event_text_matches?(disable_events, [/disabled CFDP engine/i, /engine already disabled/i])
  enable_seen = event_text_matches?(enable_events, [/enabled CFDP engine/i, /engine already enabled/i])
  {
    label: label,
    before_hk: before_hk,
    disable_command: disable,
    disable_events: disable_events,
    hk_manage: hk_manage,
    enable_command: enable,
    enable_events: enable_events,
    after_hk: after_hk,
    disable_event_observed: disable_seen,
    enable_event_observed: enable_seen,
    confirmed: disable[:ok] == true && hk_manage.is_a?(Hash) && !hk_manage[:error_class] && enable[:ok] == true
  }
end

def run_cf_dequeue_trial(label, tag)
  src_name = "/cf/sp4cf_#{tag}.dat"
  src_host = host_cf_path(src_name)
  File.write(src_host, "SP004 CF dequeue trial #{label} #{Time.now.utc.iso8601}\n")
  purge = cf_purge_downlink_pending_history(0)
  purge_events = collect_events(1.5, 0.15)
  sleep(1.5)
  before_hk = read_cf_hk(true)
  tx = cf_tx_file(src_name, "/tmp/sp4cf_#{tag}.dat", 0, 23, 1, 0, 1)
  tx_events = collect_events(2.0, 0.15)
  sleep(6.0)
  after_hk = read_cf_hk(true)
  sent_pdu_delta = counter_delta(after_hk, before_hk, :ch1_sent_pdu)
  pending_delta = counter_delta(after_hk, before_hk, :ch1_pending_q_size)
  active_delta = counter_delta(after_hk, before_hk, :ch1_active_q_size)
  tx_initiated = event_text_matches?(tx_events, [/file transfer successfully initiated/i])
  {
    label: label,
    source_host_file: src_host,
    source_cf_file: src_name,
    purge_command: purge,
    purge_events: purge_events,
    before_hk: before_hk,
    tx_command: tx,
    tx_events: tx_events,
    tx_initiated: tx_initiated,
    wait_for_scheduler_wakeups_seconds: 6.0,
    after_hk: after_hk,
    sent_pdu_delta: sent_pdu_delta,
    pending_delta: pending_delta,
    active_delta: active_delta,
    pending_queue_retained: after_hk.is_a?(Hash) && before_hk.is_a?(Hash) && after_hk[:ch1_pending_q_size].to_i > before_hk[:ch1_pending_q_size].to_i,
    sent_pdu_observed: sent_pdu_delta.to_i > 0
  }
rescue Exception => error
  { label: label, error_class: error.class.to_s, error: error.message }
end

def to_tlm_target
  @to_tlm_target ||= ['TO', 'CFS'].find { |target| telemetry_packet_exists?(target, 'TO_HKPACKET') } || 'TO'
end

def read_to_hk(refresh = true)
  request_table_owner_hk('TO.to_config') if refresh
  sleep(0.3) if refresh

  target = to_tlm_target
  {
    target: target,
    received_count: tlm_i_optional(target, 'TO_HKPACKET', 'RECEIVED_COUNT'),
    packet_time: tlm_i_optional(target, 'TO_HKPACKET', 'PACKET_TIMESECONDS'),
    cmd_counter: tlm_i(target, 'TO_HKPACKET', 'CMDCOUNTER'),
    err_counter: tlm_i(target, 'TO_HKPACKET', 'ERRCOUNTER'),
    msg_sub_count: tlm_i(target, 'TO_HKPACKET', 'MSGSUBCNT'),
    msg_sub_err_count: tlm_i(target, 'TO_HKPACKET', 'MSGSUBERRCNT'),
    tbl_update_count: tlm_i(target, 'TO_HKPACKET', 'TBLUPDATECNT'),
    tbl_err_count: tlm_i_first(target, 'TO_HKPACKET', ['TBLERRCNT', 'TBLEERRCNT']),
    config_routes: tlm_i(target, 'TO_HKPACKET', 'CONFIGROUTES'),
    enabled_routes: tlm_i(target, 'TO_HKPACKET', 'ENABLEDROUTES')
  }
rescue Exception => error
  { error_class: error.class.to_s, error: error.message }
end

TO_CONFIG_ENTRY_SIZE = 20
TO_CONFIG_ENTRY_COUNT = 100
TO_CONFIG_STATE_OFFSET = 18
TO_CONFIG_HEADER_SIZE = 116

def parse_to_config_table_file(path)
  return { ok: false, path: path, reason: 'file_missing' } unless File.exist?(path)

  bytes = File.binread(path)
  header_size = bytes.bytesize - (TO_CONFIG_ENTRY_SIZE * TO_CONFIG_ENTRY_COUNT)
  header_size = TO_CONFIG_HEADER_SIZE if header_size < 0
  entries = []
  TO_CONFIG_ENTRY_COUNT.times do |index|
    offset = header_size + (index * TO_CONFIG_ENTRY_SIZE)
    break if offset + TO_CONFIG_ENTRY_SIZE > bytes.bytesize

    chunk = bytes.byteslice(offset, TO_CONFIG_ENTRY_SIZE)
    msgid = chunk.byteslice(0, 4).unpack1('V')
    msg_limit = chunk.byteslice(6, 2).unpack1('v')
    route_mask = chunk.byteslice(8, 2).unpack1('v')
    state = chunk.byteslice(TO_CONFIG_STATE_OFFSET, 2).unpack1('v')
    used = msgid != 0
    entries << {
      index: index,
      msgid: msgid,
      msgid_hex: format('0x%04X', msgid),
      msg_limit: msg_limit,
      route_mask: route_mask,
      route_mask_hex: format('0x%04X', route_mask),
      state: state,
      used: used
    }
  end

  used_entries = entries.select { |entry| entry[:used] }
  {
    ok: true,
    path: path,
    size: bytes.bytesize,
    header_size: header_size,
    entry_size: TO_CONFIG_ENTRY_SIZE,
    entry_count: entries.length,
    used_count: used_entries.length,
    enabled_used_count: used_entries.count { |entry| entry[:state].to_i != 0 },
    disabled_used_count: used_entries.count { |entry| entry[:state].to_i == 0 },
    sample_entries: used_entries.first(8),
    selected_entries: used_entries.values_at(0, 14, 19, 25, 49).compact
  }
rescue Exception => error
  { ok: false, path: path, error_class: error.class.to_s, error: error.message }
end

def dump_active_table_to_file(target_id, table_name, dump_cf_path, timeout = 10.0)
  dump_host_path = host_cf_path(dump_cf_path)
  remove_file(dump_host_path)
  before_tbl = read_tbl_safe
  command = sp004_run_profile(
    SP004_PROFILE_TBL_DUMP_ACTIVE,
    target_id,
    table_name: table_name,
    dump_filename: dump_cf_path
  )
  events = collect_events(timeout)
  dumped_file = wait_for_file(dump_host_path, timeout)
  after_tbl = read_tbl_safe
  parsed = parse_to_config_table_file(dump_host_path)
  {
    command: command,
    before_tbl: before_tbl,
    events: events,
    dumped_file: dumped_file,
    after_tbl: after_tbl,
    parsed_table: parsed
  }
end

CF_CONFIG_TABLE_SIZE = 1260
CF_CONFIG_HEADER_SIZE = 116
CF_CONFIG_CHANNEL_COUNT = 2
CF_CONFIG_CHANNEL_SIZE = 600
CF_CONFIG_CHANNEL_OFFSET = 12
CF_CONFIG_CH_MAX_OUT_OFFSET = 0
CF_CONFIG_CH_RX_MAX_OFFSET = 4
CF_CONFIG_CH_ACK_TIMER_OFFSET = 8
CF_CONFIG_CH_NAK_TIMER_OFFSET = 12
CF_CONFIG_CH_INACTIVITY_OFFSET = 16
CF_CONFIG_CH_ACK_LIMIT_OFFSET = 20
CF_CONFIG_CH_NAK_LIMIT_OFFSET = 21
CF_CONFIG_CH_MID_INPUT_OFFSET = 24
CF_CONFIG_CH_MID_OUTPUT_OFFSET = 28
CF_CONFIG_CH_PIPE_DEPTH_OFFSET = 32
CF_CONFIG_CH_POLL0_OFFSET = 36
CF_CONFIG_CH_SEM_NAME_OFFSET = 576
CF_CONFIG_CH_DEQUEUE_OFFSET = 596
CF_CONFIG_POLL_SIZE = 108
CF_CONFIG_POLL_INTERVAL_OFFSET = 0
CF_CONFIG_POLL_PRIORITY_OFFSET = 4
CF_CONFIG_POLL_CLASS_OFFSET = 8
CF_CONFIG_POLL_DEST_EID_OFFSET = 12
CF_CONFIG_POLL_SRC_DIR_OFFSET = 16
CF_CONFIG_POLL_DST_DIR_OFFSET = 60
CF_CONFIG_POLL_ENABLED_OFFSET = 104
CF_CONFIG_PATH_SIZE = 44
CF_CONFIG_SEM_NAME_SIZE = 20
CF_CONFIG_CHUNK_OFFSET = 1212
CF_CONFIG_TMP_DIR_OFFSET = 1214


def parse_cf_config_table_file(path)
  return { ok: false, path: path, reason: 'file_missing' } unless File.exist?(path)

  bytes = File.binread(path)
  header_size = bytes.bytesize - CF_CONFIG_TABLE_SIZE
  header_size = CF_CONFIG_HEADER_SIZE if header_size < 0
  data = bytes.byteslice(header_size, CF_CONFIG_TABLE_SIZE)
  return { ok: false, path: path, size: bytes.bytesize, reason: 'cf_config_payload_too_short', header_size: header_size } unless data && data.bytesize >= CF_CONFIG_TABLE_SIZE

  channels = []
  CF_CONFIG_CHANNEL_COUNT.times do |chan_index|
    base = CF_CONFIG_CHANNEL_OFFSET + (chan_index * CF_CONFIG_CHANNEL_SIZE)
    polls = []
    5.times do |poll_index|
      pbase = base + CF_CONFIG_CH_POLL0_OFFSET + (poll_index * CF_CONFIG_POLL_SIZE)
      polls << {
        index: poll_index,
        interval_sec: data.byteslice(pbase + CF_CONFIG_POLL_INTERVAL_OFFSET, 4).unpack1('V'),
        priority: data.getbyte(pbase + CF_CONFIG_POLL_PRIORITY_OFFSET),
        cfdp_class: data.byteslice(pbase + CF_CONFIG_POLL_CLASS_OFFSET, 4).unpack1('V'),
        dest_eid: data.byteslice(pbase + CF_CONFIG_POLL_DEST_EID_OFFSET, 4).unpack1('V'),
        src_dir: clean_string(data.byteslice(pbase + CF_CONFIG_POLL_SRC_DIR_OFFSET, CF_CONFIG_PATH_SIZE)),
        dst_dir: clean_string(data.byteslice(pbase + CF_CONFIG_POLL_DST_DIR_OFFSET, CF_CONFIG_PATH_SIZE)),
        enabled: data.getbyte(pbase + CF_CONFIG_POLL_ENABLED_OFFSET)
      }
    end

    channels << {
      index: chan_index,
      max_outgoing_messages_per_wakeup: data.byteslice(base + CF_CONFIG_CH_MAX_OUT_OFFSET, 4).unpack1('V'),
      rx_max_messages_per_wakeup: data.byteslice(base + CF_CONFIG_CH_RX_MAX_OFFSET, 4).unpack1('V'),
      ack_timer_s: data.byteslice(base + CF_CONFIG_CH_ACK_TIMER_OFFSET, 4).unpack1('V'),
      nak_timer_s: data.byteslice(base + CF_CONFIG_CH_NAK_TIMER_OFFSET, 4).unpack1('V'),
      inactivity_timer_s: data.byteslice(base + CF_CONFIG_CH_INACTIVITY_OFFSET, 4).unpack1('V'),
      ack_limit: data.getbyte(base + CF_CONFIG_CH_ACK_LIMIT_OFFSET),
      nak_limit: data.getbyte(base + CF_CONFIG_CH_NAK_LIMIT_OFFSET),
      mid_input: data.byteslice(base + CF_CONFIG_CH_MID_INPUT_OFFSET, 4).unpack1('V'),
      mid_input_hex: format('0x%04X', data.byteslice(base + CF_CONFIG_CH_MID_INPUT_OFFSET, 4).unpack1('V')),
      mid_output: data.byteslice(base + CF_CONFIG_CH_MID_OUTPUT_OFFSET, 4).unpack1('V'),
      mid_output_hex: format('0x%04X', data.byteslice(base + CF_CONFIG_CH_MID_OUTPUT_OFFSET, 4).unpack1('V')),
      pipe_depth_input: data.byteslice(base + CF_CONFIG_CH_PIPE_DEPTH_OFFSET, 2).unpack1('v'),
      polldirs: polls,
      sem_name: clean_string(data.byteslice(base + CF_CONFIG_CH_SEM_NAME_OFFSET, CF_CONFIG_SEM_NAME_SIZE)),
      dequeue_enabled: data.getbyte(base + CF_CONFIG_CH_DEQUEUE_OFFSET)
    }
  end

  {
    ok: true,
    path: path,
    size: bytes.bytesize,
    header_size: header_size,
    table_size: CF_CONFIG_TABLE_SIZE,
    ticks_per_second: data.byteslice(0, 4).unpack1('V'),
    rx_crc_calc_bytes_per_wakeup: data.byteslice(4, 4).unpack1('V'),
    local_eid: data.byteslice(8, 4).unpack1('V'),
    channels: channels,
    outgoing_file_chunk_size: data.byteslice(CF_CONFIG_CHUNK_OFFSET, 2).unpack1('v'),
    tmp_dir: clean_string(data.byteslice(CF_CONFIG_TMP_DIR_OFFSET, CF_CONFIG_PATH_SIZE))
  }
rescue Exception => error
  { ok: false, path: path, error_class: error.class.to_s, error: error.message }
end

def dump_active_cf_config_table(timeout = 10.0)
  dump_host_path = host_cf_path(CF_CONFIG_DUMP_TBL)
  remove_file(dump_host_path)
  before_tbl = read_tbl_safe
  command = sp004_run_profile(
    SP004_PROFILE_TBL_DUMP_ACTIVE,
    SP004_TARGET_CF_CONFIG,
    table_name: 'CF.config_table',
    dump_filename: CF_CONFIG_DUMP_TBL
  )
  events = collect_events(timeout)
  dumped_file = wait_for_file(dump_host_path, timeout)
  after_tbl = read_tbl_safe
  parsed = parse_cf_config_table_file(dump_host_path)
  {
    command: command,
    before_tbl: before_tbl,
    events: events,
    dumped_file: dumped_file,
    after_tbl: after_tbl,
    parsed_table: parsed
  }
end

def wait_for_to_table_update(baseline_hk, timeout = 10.0, interval = 0.5)
  samples = []
  last = wait_until(timeout, interval) do
    current = read_to_hk(true)
    table_update_delta = counter_delta(current, baseline_hk, :tbl_update_count)
    tbl_err_delta = counter_delta(current, baseline_hk, :tbl_err_count)
    samples << current.merge(table_update_delta: table_update_delta, tbl_err_delta: tbl_err_delta) if current.is_a?(Hash) && samples.length < 12
    {
      matched: current.is_a?(Hash) && !current[:error_class] && table_update_delta.to_i > 0,
      current: current,
      table_update_delta: table_update_delta,
      tbl_err_delta: tbl_err_delta
    }
  end

  last.merge(baseline_hk: baseline_hk, samples: samples)
end

def wait_for_to_config_subscription_change(baseline_hk, timeout = 14.0, interval = 0.7)
  samples = []
  baseline_subs = baseline_hk.fetch(:msg_sub_count, nil).to_i if baseline_hk.is_a?(Hash) && !baseline_hk[:error_class]
  baseline_updates = baseline_hk.fetch(:tbl_update_count, nil).to_i if baseline_hk.is_a?(Hash) && !baseline_hk[:error_class]
  baseline_sub_errors = baseline_hk.fetch(:msg_sub_err_count, 0).to_i if baseline_hk.is_a?(Hash) && !baseline_hk[:error_class]

  last = wait_until(timeout, interval) do
    current = read_to_hk(true)
    table_update_delta = counter_delta(current, baseline_hk, :tbl_update_count)
    msg_sub_delta = counter_delta(current, baseline_hk, :msg_sub_count)
    msg_sub_err_delta = counter_delta(current, baseline_hk, :msg_sub_err_count)
    samples << current.merge(
      table_update_delta: table_update_delta,
      msg_sub_delta: msg_sub_delta,
      msg_sub_err_delta: msg_sub_err_delta
    ) if current.is_a?(Hash) && samples.length < 12

    matched = current.is_a?(Hash) && !current[:error_class] &&
              !baseline_subs.nil? && !baseline_updates.nil? &&
              table_update_delta.to_i > 0 && msg_sub_delta.to_i.abs >= 10

    {
      matched: matched,
      current: current,
      table_update_delta: table_update_delta,
      msg_sub_delta: msg_sub_delta,
      msg_sub_err_delta: msg_sub_err_delta
    }
  end

  last.merge(
    baseline_hk: baseline_hk,
    baseline_msg_sub_count: baseline_subs,
    baseline_tbl_update_count: baseline_updates,
    baseline_msg_sub_err_count: baseline_sub_errors,
    samples: samples
  )
end

def trigger_es_hk_packets(count = 5, interval = 0.4)
  results = []
  count.times do
    results << request_es_hk
    sleep(interval)
  end
  results
end

def lc_tlm_target
  @lc_tlm_target ||= ['CFS', 'LC'].find { |target| telemetry_packet_exists?(target, 'LC_HKPACKET') } || 'CFS'
end

def read_lc_hk(refresh = true)
  request_table_owner_hk('LC.LC_WDT') if refresh
  sleep(0.25) if refresh

  target = lc_tlm_target
  current_state = tlm_raw_i(target, 'LC_HKPACKET', 'CURRENTLCSTATE')
  wp0 = tlm_raw_i(target, 'LC_HKPACKET', 'WPRESULTS_0')
  {
    target: target,
    current_lc_state: current_state,
    current_lc_state_name: LC_STATE_NAMES.fetch(current_state, "UNKNOWN_#{current_state}"),
    wps_in_use: tlm_i(target, 'LC_HKPACKET', 'WPSINUSE'),
    active_aps: tlm_i(target, 'LC_HKPACKET', 'ACTIVEAPS'),
    ap_sample_count: tlm_i(target, 'LC_HKPACKET', 'APSAMPLECOUNT'),
    monitored_msg_count: tlm_i(target, 'LC_HKPACKET', 'MONITOREDMSGCOUNT'),
    rts_exec_count: tlm_i(target, 'LC_HKPACKET', 'RTSEXECCOUNT'),
    passive_rts_exec_count: tlm_i(target, 'LC_HKPACKET', 'PASSIVERTSEXECCOUNT'),
    wpresults_0: wp0,
    wpresults_0_name: LC_WATCH_RESULT_NAMES.fetch(wp0, "UNKNOWN_#{wp0}")
  }
rescue Exception => error
  { error_class: error.class.to_s, error: error.message }
end

def lc_defined_ap_result?(value)
  value.to_i >= 4
end

def lc_active_ap_result?(value)
  (4..7).include?(value.to_i)
end

def read_lc_ap_results(indices, refresh = true)
  request_table_owner_hk('LC.LC_ADT') if refresh
  sleep(0.25) if refresh

  target = lc_tlm_target
  results = Array(indices).each_with_object({}) do |index, values|
    value = tlm_raw_i(target, 'LC_HKPACKET', "APRESULTS_#{index}")
    values[index] = {
      value: value,
      name: LC_ACTION_RESULT_NAMES.fetch(value, "UNKNOWN_#{value}"),
      defined: lc_defined_ap_result?(value),
      active: lc_active_ap_result?(value)
    }
  end
  {
    target: target,
    indices: Array(indices),
    results: results,
    defined_count: results.values.count { |entry| entry[:defined] },
    active_count: results.values.count { |entry| entry[:active] }
  }
rescue Exception => error
  { error_class: error.class.to_s, error: error.message, indices: Array(indices) }
end

def lc_ap_entry(snapshot, index)
  return {} unless snapshot.is_a?(Hash)

  snapshot.fetch(:results, {})[index] || snapshot.fetch(:results, {})[index.to_s] || {}
end

def wait_for_lc_adt_attack_shape(timeout = 10.0, interval = 0.5)
  indices = [LC_ATTACK_ADT_AP] + LC_MISSION_ADT_AP_RANGE
  samples = []
  last = wait_until(timeout, interval) do
    current = read_lc_ap_results(indices, true)
    samples << current if samples.length < 12
    ap0 = lc_ap_entry(current, LC_ATTACK_ADT_AP)
    mission_defined = LC_MISSION_ADT_AP_RANGE.count { |index| lc_ap_entry(current, index)[:defined] }
    matched = current.is_a?(Hash) && !current[:error_class] && mission_defined == 0 && ap0[:active] == true
    { matched: matched, current: current, attack_ap0: ap0, mission_defined_count: mission_defined }
  end
  last.merge(samples: samples, expected_attack_ap: LC_ATTACK_ADT_AP, expected_mission_defined_count: 0)
end

def sample_lc_actionpoint_effect(ap_index = LC_ATTACK_ADT_AP, timeout = 8.0, interval = 0.5)
  before_hk = read_lc_hk(true)
  before_ap = read_lc_ap_results([ap_index], false)
  samples = []
  command_results = []
  last = wait_until(timeout, interval) do
    command_results << request_lc_sample_ap(ap_index, ap_index, 0)
    sleep(0.25)
    current_hk = read_lc_hk(true)
    current_ap = read_lc_ap_results([ap_index], false)
    ap_sample_delta = counter_delta(current_hk, before_hk, :ap_sample_count)
    rts_exec_delta = counter_delta(current_hk, before_hk, :rts_exec_count)
    passive_rts_exec_delta = counter_delta(current_hk, before_hk, :passive_rts_exec_count)
    sample = {
      current_hk: current_hk,
      current_ap: current_ap,
      ap_sample_delta: ap_sample_delta,
      rts_exec_delta: rts_exec_delta,
      passive_rts_exec_delta: passive_rts_exec_delta
    }
    samples << sample if samples.length < 12
    { matched: ap_sample_delta.to_i > 0, **sample }
  end

  last.merge(
    before_hk: before_hk,
    before_ap: before_ap,
    command_results: command_results,
    samples: samples,
    sampled_ap: ap_index
  )
end

def wait_for_lc_wps_in_use(expected, timeout = 10.0, interval = 0.5)
  samples = []
  last = wait_until(timeout, interval) do
    current = read_lc_hk(true)
    samples << current if samples.length < 12
    { matched: current.is_a?(Hash) && !current[:error_class] && current[:wps_in_use].to_i == expected.to_i, current: current }
  end
  last.merge(expected_wps_in_use: expected, samples: samples)
end

def sample_lc_es_hk_watchpoint_effect(timeout = 10.0, interval = 0.5)
  before = read_lc_hk(true)
  samples = [before]
  trigger_results = []
  last = nil
  deadline = Time.now + timeout

  until Time.now >= deadline
    trigger_results << request_es_hk
    sleep(interval)
    current = read_lc_hk(true)
    samples << current if samples.length < 16
    delta = counter_delta(current, before, :monitored_msg_count)
    matched = current.is_a?(Hash) && !current[:error_class] && delta.to_i > 0
    last = { matched: matched, before: before, current: current, monitored_msg_delta: delta }
    break if matched
  end

  (last || { matched: false, before: before, current: samples.last, monitored_msg_delta: counter_delta(samples.last, before, :monitored_msg_count) }).merge(
    trigger: 'CFE_ES_SEND_HK_MID',
    trigger_results: trigger_results,
    samples: samples
  )
end

def read_sch_hk(refresh = true)
  request_table_owner_hk('SCH.SCHED_DEF') if refresh
  sleep(0.2) if refresh

  {
    received_count: tlm_i('CFS', 'SCH_HKPACKET', 'RECEIVED_COUNT'),
    packet_time: tlm('CFS SCH_HKPACKET PACKET_TIMESECONDS'),
    schedule_activity_success_count: tlm_i('CFS', 'SCH_HKPACKET', 'SCHEDULEACTIVITYSUCCESSCOUNT'),
    schedule_activity_failure_count: tlm_i('CFS', 'SCH_HKPACKET', 'SCHEDULEACTIVITYFAILURECOUNT'),
    slots_processed_count: tlm_i('CFS', 'SCH_HKPACKET', 'SLOTSPROCESSEDCOUNT'),
    table_pass_count: tlm_i('CFS', 'SCH_HKPACKET', 'TABLEPASSCOUNT'),
    next_slot_number: tlm_i('CFS', 'SCH_HKPACKET', 'NEXTSLOTNUMBER')
  }
rescue Exception => error
  { error_class: error.class.to_s, error: error.message }
end

def counter_delta(after, before, key)
  return nil unless after.is_a?(Hash) && before.is_a?(Hash)
  return nil if after[:error_class] || before[:error_class]

  after.fetch(key, 0).to_i - before.fetch(key, 0).to_i
end

def sample_sch_activity_window(duration = 8.0, interval = 1.0)
  start_state = read_sch_hk(true)
  states = [start_state]
  deadline = Time.now + duration

  until Time.now >= deadline
    sleep(interval)
    states << read_sch_hk(true)
  end

  finish_state = states.last
  {
    start: start_state,
    finish: finish_state,
    states: states,
    duration_seconds: duration,
    schedule_activity_success_delta: counter_delta(finish_state, start_state, :schedule_activity_success_count),
    schedule_activity_failure_delta: counter_delta(finish_state, start_state, :schedule_activity_failure_count),
    slots_processed_delta: counter_delta(finish_state, start_state, :slots_processed_count),
    table_pass_delta: counter_delta(finish_state, start_state, :table_pass_count),
    received_delta: counter_delta(finish_state, start_state, :received_count)
  }
end

def sch_activity_window_normal?(sample)
  sample.is_a?(Hash) &&
    sample[:schedule_activity_success_delta].to_i > 0 &&
    sample[:slots_processed_delta].to_i > 0
end

def sch_activity_suppressed?(sample)
  sample.is_a?(Hash) &&
    sample[:slots_processed_delta].to_i > 0 &&
    sample[:schedule_activity_success_delta].to_i == 0
end

def request_sch_diag
  cmd_first(['CFS SCH_SEND_DIAG_TLM', 'SCH SCH_SEND_DIAG_TLM'])
end

def sch_diag_msgid_item(table_index)
  "MSGIDS_#{(table_index.to_i * 2) + 1}"
end

def force_sch_table_manage
  request_table_owner_hk('SCH.MSG_DEFS')
  sleep(0.8)
  request_table_owner_hk('SCH.MSG_DEFS')
  sleep(0.8)
end

def read_sch_diag_entry_msgid(table_index = 245)
  force_sch_table_manage
  command = request_sch_diag
  sleep(1.0)
  item = sch_diag_msgid_item(table_index)
  msgid = tlm_i('CFS', 'SCH_DIAGPACKET', item)
  {
    command: command,
    table_index: table_index,
    item: item,
    received_count: tlm_i('CFS', 'SCH_DIAGPACKET', 'RECEIVED_COUNT'),
    msgid: msgid,
    msgid_hex: format('0x%04X', msgid)
  }
rescue Exception => error
  { table_index: table_index, item: sch_diag_msgid_item(table_index), error_class: error.class.to_s, error: error.message }
end

def wait_for_sch_diag_entry_msgid(expected_msgid, table_index = 245, timeout = 12.0, interval = 1.0)
  deadline = Time.now + timeout
  samples = []
  last = nil

  until Time.now >= deadline
    last = read_sch_diag_entry_msgid(table_index)
    samples << last
    if last.is_a?(Hash) && last[:msgid].to_i == expected_msgid.to_i
      return last.merge(matched: true, expected_msgid: expected_msgid, expected_msgid_hex: format('0x%04X', expected_msgid), samples: samples)
    end
    sleep(interval)
  end

  (last || {}).merge(matched: false, expected_msgid: expected_msgid, expected_msgid_hex: format('0x%04X', expected_msgid), samples: samples)
end

def sample_sch_automatic_hk_window(duration = 10.0, interval = 1.0)
  start_state = read_sch_hk(false)
  states = [start_state]
  deadline = Time.now + duration

  until Time.now >= deadline
    sleep(interval)
    states << read_sch_hk(false)
  end

  before_manual_refresh = states.last
  manual_refresh = read_sch_hk(true)
  {
    start: start_state,
    before_manual_refresh: before_manual_refresh,
    manual_refresh: manual_refresh,
    states: states,
    duration_seconds: duration,
    automatic_sch_hk_received_delta: counter_delta(before_manual_refresh, start_state, :received_count),
    manual_refresh_received_delta: counter_delta(manual_refresh, before_manual_refresh, :received_count),
    schedule_activity_success_delta_after_manual_refresh: counter_delta(manual_refresh, start_state, :schedule_activity_success_count),
    slots_processed_delta_after_manual_refresh: counter_delta(manual_refresh, start_state, :slots_processed_count),
    table_pass_delta_after_manual_refresh: counter_delta(manual_refresh, start_state, :table_pass_count)
  }
end

def sch_automatic_hk_active?(sample)
  sample.is_a?(Hash) &&
    sample[:automatic_sch_hk_received_delta].to_i > 0 &&
    sample[:schedule_activity_success_delta_after_manual_refresh].to_i > 0 &&
    sample[:slots_processed_delta_after_manual_refresh].to_i > 0
end

def sch_automatic_hk_hijacked?(sample)
  sample.is_a?(Hash) &&
    sample[:automatic_sch_hk_received_delta].to_i == 0 &&
    sample[:schedule_activity_success_delta_after_manual_refresh].to_i > 0 &&
    sample[:slots_processed_delta_after_manual_refresh].to_i > 0
end

def capture_attack_effect_baseline(spec)
  case spec[:effect_check]
  when :ds_malicious_output_files
    {
      required: true,
      kind: 'ds_malicious_output_files',
      patterns: ['sp004ds*.bad', 'sp004hk*.bad'],
      snapshot: cf_file_snapshot(['sp004ds*.bad', 'sp004hk*.bad'])
    }
  when :ds_filter_es_hk_to_file_index_zero
    fixture = run_table_cycle(SP004_TARGET_DS_FILE, false, 'effect_fixture_ds_file_table', 'DS.FILE_TBL')
    {
      required: true,
      kind: 'ds_filter_es_hk_to_file_index_zero',
      ds_file_fixture: fixture,
      ds_file_fixture_active: observed_table_activated?(fixture, 'DS.FILE_TBL')
    }
  when :lc_wdt_replace_mission_watchpoints_with_es_hk_true
    baseline_wps = wait_for_lc_wps_in_use(LC_MISSION_WDT_EXPECTED_WPS, 12.0, 0.5)
    {
      required: true,
      kind: 'lc_wdt_replace_mission_watchpoints_with_es_hk_true',
      expected_mission_wps_in_use: LC_MISSION_WDT_EXPECTED_WPS,
      expected_attack_wps_in_use: LC_ATTACK_WDT_EXPECTED_WPS,
      expected_attack_wp0_result: 'TRUE',
      baseline_wps: baseline_wps,
      baseline_mission_watchpoints_observed: baseline_wps[:matched] == true
    }
  when :lc_adt_replace_mission_actionpoints_with_ap0_rts
    baseline_mission = read_lc_ap_results(LC_MISSION_ADT_AP_RANGE, true)
    baseline_ap0 = read_lc_ap_results([LC_ATTACK_ADT_AP], false)
    {
      required: true,
      kind: 'lc_adt_replace_mission_actionpoints_with_ap0_rts',
      expected_mission_actionpoints: LC_MISSION_ADT_EXPECTED_APS,
      expected_mission_ap_range: LC_MISSION_ADT_AP_RANGE,
      expected_attack_ap: LC_ATTACK_ADT_AP,
      baseline_mission: baseline_mission,
      baseline_ap0: baseline_ap0,
      baseline_mission_actionpoints_observed: baseline_mission[:defined_count].to_i == LC_MISSION_ADT_EXPECTED_APS,
      baseline_attack_ap0_unused: !lc_ap_entry(baseline_ap0, LC_ATTACK_ADT_AP)[:defined]
    }
  when :cf_config_table_disable_dequeue_and_reidentify
    original_table = parse_cf_config_table_file(host_cf_path(spec[:restore_tbl]))
    malicious_table = parse_cf_config_table_file(host_cf_path(spec[:attack_tbl]))
    baseline_sync = cf_sync_config_table_with_engine_gate('baseline_original_cf_config_engine_gate_sync')
    baseline_trial = run_cf_dequeue_trial('baseline_original_cf_dequeue_processes_pending_tx', 'baseline')
    {
      required: true,
      kind: 'cf_config_table_disable_dequeue_and_reidentify',
      original_table_source: '/home/leejm/nos3/cfg/nos3_defs/tables/cf_def_config.c',
      malicious_table_source: '/home/leejm/nos3/cfg/nos3_defs/tables/sp004_cf_config_bad.c',
      validation_function: '/home/leejm/nos3/fsw/apps/cf/fsw/src/cf_app.c:112 CF_ValidateConfigTable',
      table_update_gate: '/home/leejm/nos3/fsw/apps/cf/fsw/src/cf_app.c:64 CF_CheckTables only manages table when engine is disabled',
      expected_original_local_eid: 24,
      expected_attack_local_eid: 125,
      expected_original_dequeue_enabled: 1,
      expected_attack_dequeue_enabled: 0,
      original_table: original_table,
      malicious_table: malicious_table,
      baseline_sync: baseline_sync,
      baseline_trial: baseline_trial,
      original_table_shape_ok: original_table[:ok] && original_table[:local_eid].to_i == 24 && original_table[:channels].all? { |ch| ch[:dequeue_enabled].to_i == 1 },
      malicious_table_shape_ok: malicious_table[:ok] && malicious_table[:local_eid].to_i == 125 && malicious_table[:channels].all? { |ch| ch[:dequeue_enabled].to_i == 0 },
      baseline_dequeue_processes_tx: baseline_trial[:tx_initiated] == true && (baseline_trial[:sent_pdu_observed] == true || baseline_trial[:pending_queue_retained] == false)
    }
  when :to_config_disable_used_entries
    baseline_hk = read_to_hk(true)
    original_table = parse_to_config_table_file(host_cf_path(spec[:restore_tbl]))
    malicious_table = parse_to_config_table_file(host_cf_path(spec[:attack_tbl]))
    {
      required: true,
      kind: 'to_config_disable_used_entries',
      original_table_source: '/home/leejm/nos3/cfg/nos3_defs/tables/to_config.c',
      malicious_table_source: '/home/leejm/Space OS/cfs-security-benchmark/security_suites/space_platform/injections/sp004_table_tamper/components/sp004_table_tamper/fsw/cfs/tables/sp004_to_config_bad.c',
      expected_original_used_entries: original_table[:used_count],
      expected_attack_used_entries: malicious_table[:used_count],
      expected_attack_entry_state: 0,
      baseline_hk: baseline_hk,
      original_table: original_table,
      malicious_table: malicious_table,
      baseline_to_hk_observed: baseline_hk.is_a?(Hash) && !baseline_hk[:error_class],
      original_table_enabled: original_table[:ok] && original_table[:used_count].to_i > 0 && original_table[:disabled_used_count].to_i == 0,
      malicious_table_disables_used_entries: malicious_table[:ok] && malicious_table[:used_count].to_i > 0 && malicious_table[:enabled_used_count].to_i == 0
    }
  when :sc_rts001_ds_state_command_replaced
    original_source = sc_rts001_source_ds_state('/home/leejm/nos3/cfg/nos3_defs/tables/sc_rts001.c')
    malicious_source = sc_rts001_source_ds_state('/home/leejm/nos3/cfg/nos3_defs/tables/sp004_sc_rts001_bad.c')
    baseline_trial = run_sc_rts1_ds_state_trial('baseline_original_rts1_enables_ds', DS_DISABLED, DS_ENABLED, 20.0)
    {
      required: true,
      kind: 'sc_rts001_ds_state_command_replaced',
      original_table_source: original_source,
      malicious_table_source: malicious_source,
      expected_original_ds_state_command: DS_ENABLED,
      expected_attack_ds_state_command: DS_DISABLED,
      baseline_trial: baseline_trial,
      baseline_original_source_enables_ds: original_source[:ok] && original_source[:ds_cmd1_enable_state].to_i == DS_ENABLED,
      malicious_source_disables_ds: malicious_source[:ok] && malicious_source[:ds_cmd1_enable_state].to_i == DS_DISABLED,
      baseline_rts1_enables_ds: baseline_trial[:confirmed] == true
    }
  when :sc_ats1_first_command_reset_instead_of_noop
    original_source = sc_ats1_source_first_cmd('/home/leejm/nos3/cfg/nos3_defs/tables/sc_ats1.c')
    malicious_source = sc_ats1_source_first_cmd('/home/leejm/nos3/cfg/nos3_defs/tables/sp004_sc_ats1_bad.c')
    sch_sched_fixture = run_table_cycle(SP004_TARGET_SCH_SCHED, true, 'effect_fixture_restore_sch_sched_for_sc_ats1', 'SCH.SCHED_DEF')
    sch_msg_fixture = run_table_cycle(SP004_TARGET_SCH_MSG, true, 'effect_fixture_restore_sch_msg_for_sc_ats1', 'SCH.MSG_DEFS')
    sleep(2.0)
    baseline_trial = run_sc_ats1_first_command_trial('baseline_original_ats1_first_command_noop', false, 45.0)
    {
      required: true,
      kind: 'sc_ats1_first_command_reset_instead_of_noop',
      original_table_source: original_source,
      malicious_table_source: malicious_source,
      expected_original_first_command: 'SC_NOOP_CC',
      expected_attack_first_command: 'SC_RESET_COUNTERS_CC',
      sch_sched_fixture: sch_sched_fixture,
      sch_msg_fixture: sch_msg_fixture,
      sch_sched_fixture_restored: observed_table_activated?(sch_sched_fixture, 'SCH.SCHED_DEF'),
      sch_msg_fixture_restored: observed_table_activated?(sch_msg_fixture, 'SCH.MSG_DEFS'),
      baseline_trial: baseline_trial,
      baseline_original_source_noop: original_source[:ok] && original_source[:cmd1_command] == 'SC_NOOP_CC',
      malicious_source_resets_counters: malicious_source[:ok] && malicious_source[:cmd1_command] == 'SC_RESET_COUNTERS_CC',
      baseline_ats1_runs_noop_without_reset: baseline_trial[:confirmed] == true
    }
  when :sch_schedule_activity_suppression
    baseline_sample = sample_sch_activity_window(8.0, 1.0)
    {
      required: true,
      kind: 'sch_schedule_activity_suppression',
      baseline_sample: baseline_sample,
      baseline_activity_observed: sch_activity_window_normal?(baseline_sample)
    }
  when :sch_message_hijack_sch_hk_to_evs_hk
    baseline_diag = wait_for_sch_diag_entry_msgid(SCH_SEND_HK_MID, 245, 14.0, 1.0)
    baseline_sample = sample_sch_automatic_hk_window(10.0, 1.0)
    {
      required: true,
      kind: 'sch_message_hijack_sch_hk_to_evs_hk',
      schedule_table_index: 245,
      diag_item: sch_diag_msgid_item(245),
      expected_baseline_msgid: SCH_SEND_HK_MID,
      expected_attack_msgid: CFE_EVS_SEND_HK_MID,
      baseline_diag: baseline_diag,
      baseline_diag_matches_sch_hk: baseline_diag[:msgid].to_i == SCH_SEND_HK_MID,
      baseline_sample: baseline_sample,
      baseline_automatic_sch_hk_observed: sch_automatic_hk_active?(baseline_sample)
    }
  else
    { required: true, kind: 'no_profile_specific_effect_check_defined' }
  end
end

def observe_attack_effect(spec, baseline)
  case spec[:effect_check]
  when :ds_malicious_output_files
    patterns = baseline[:patterns] || ['sp004ds*.bad', 'sp004hk*.bad']
    activity = wait_for_cf_file_activity(patterns, baseline[:snapshot] || [], 12.0, 0.5)
    activity.merge(
      required: true,
      confirmed: activity[:matched],
      kind: 'ds_malicious_output_files',
      security_effect: activity[:matched] ? 'ds_wrote_to_attacker_selected_destination_file' : 'ds_malicious_destination_file_not_observed'
    )
  when :ds_filter_es_hk_to_file_index_zero
    patterns = ['sp004ds*.bad']
    before_snapshot = cf_file_snapshot(patterns)
    before_hk = read_ds_hk(true)
    trigger_results = trigger_es_hk_packets(6, 0.45)
    activity = wait_for_cf_file_activity(patterns, before_snapshot, 12.0, 0.5)
    after_hk = read_ds_hk(true)
    file_write_delta = counter_delta(after_hk, before_hk, :file_write_counter)
    passed_pkt_delta = counter_delta(after_hk, before_hk, :passed_pkt_counter)
    restore_fixture = run_table_cycle(SP004_TARGET_DS_FILE, true, 'restore_effect_fixture_ds_file_table', 'DS.FILE_TBL')
    confirmed = baseline[:ds_file_fixture_active] == true && activity[:matched] &&
                file_write_delta.to_i > 0 && passed_pkt_delta.to_i > 0
    activity.merge(
      required: true,
      confirmed: confirmed,
      kind: 'ds_filter_es_hk_to_file_index_zero',
      ds_file_fixture_active: baseline[:ds_file_fixture_active],
      trigger: 'CFE_ES_SEND_HK_MID',
      trigger_results: trigger_results,
      before_hk: before_hk,
      after_hk: after_hk,
      file_write_delta: file_write_delta,
      passed_pkt_delta: passed_pkt_delta,
      restore_ds_file_fixture: restore_fixture,
      security_effect: confirmed ?
        'ds_filter_table_routed_es_hk_packets_to_attacker_controlled_file_index_zero' :
        'ds_filter_runtime_routing_effect_not_observed'
    )
  when :lc_wdt_replace_mission_watchpoints_with_es_hk_true
    attack_wps = wait_for_lc_wps_in_use(LC_ATTACK_WDT_EXPECTED_WPS, 12.0, 0.5)
    effect_sample = sample_lc_es_hk_watchpoint_effect(12.0, 0.5)
    baseline_ok = baseline[:baseline_mission_watchpoints_observed] == true
    attack_replaced_watchpoints = attack_wps[:matched] == true
    current_state = effect_sample.dig(:current, :current_lc_state).to_i
    lc_processing_enabled = effect_sample[:current].is_a?(Hash) && !effect_sample[:current][:error_class] && current_state != 3
    runtime_effect = effect_sample[:matched] == true
    wp0_true_observed = effect_sample.dig(:current, :wpresults_0).to_i == 1
    confirmed = baseline_ok && attack_replaced_watchpoints && lc_processing_enabled && runtime_effect
    reason = if confirmed
               'lc_mission_watchpoints_replaced_and_es_hk_monitored_by_lc'
             elsif !baseline_ok
               'lc_original_mission_watchpoint_count_not_observed'
             elsif !attack_replaced_watchpoints
               'lc_wdt_update_did_not_replace_watchpoint_set'
             elsif !lc_processing_enabled
               'lc_wdt_replaced_but_lc_state_disabled_so_watchpoint_processing_not_active'
             else
               'lc_wdt_runtime_es_hk_watchpoint_effect_not_observed'
             end
    {
      required: true,
      confirmed: confirmed,
      kind: 'lc_wdt_replace_mission_watchpoints_with_es_hk_true',
      expected_mission_wps_in_use: baseline[:expected_mission_wps_in_use] || LC_MISSION_WDT_EXPECTED_WPS,
      expected_attack_wps_in_use: LC_ATTACK_WDT_EXPECTED_WPS,
      baseline_mission_watchpoints_observed: baseline_ok,
      attack_replaced_watchpoints: attack_replaced_watchpoints,
      lc_processing_enabled: lc_processing_enabled,
      runtime_effect_observed: runtime_effect,
      attack_wp0_true_observed: wp0_true_observed,
      baseline_wps: baseline[:baseline_wps],
      attack_wps: attack_wps,
      effect_sample: effect_sample,
      security_effect: reason
    }
  when :lc_adt_replace_mission_actionpoints_with_ap0_rts
    attack_shape = wait_for_lc_adt_attack_shape(12.0, 0.5)
    sample_effect = sample_lc_actionpoint_effect(LC_ATTACK_ADT_AP, 10.0, 0.5)
    baseline_ok = baseline[:baseline_mission_actionpoints_observed] == true
    ap0_was_unused = baseline[:baseline_attack_ap0_unused] == true
    attack_shape_ok = attack_shape[:matched] == true
    sample_runtime = sample_effect[:matched] == true
    rts_delta = sample_effect[:rts_exec_delta].to_i
    passive_rts_delta = sample_effect[:passive_rts_exec_delta].to_i
    confirmed = baseline_ok && ap0_was_unused && attack_shape_ok && sample_runtime
    reason = if confirmed
               'lc_mission_actionpoints_replaced_by_active_attacker_ap0_and_sampled_by_lc'
             elsif !baseline_ok
               'lc_original_mission_actionpoint_count_not_observed'
             elsif !ap0_was_unused
               'lc_attack_ap0_not_unused_in_baseline'
             elsif !attack_shape_ok
               'lc_adt_update_did_not_replace_mission_actionpoints_with_active_ap0'
             else
               'lc_adt_runtime_actionpoint_sample_effect_not_observed'
             end
    {
      required: true,
      confirmed: confirmed,
      kind: 'lc_adt_replace_mission_actionpoints_with_ap0_rts',
      expected_mission_actionpoints: baseline[:expected_mission_actionpoints] || LC_MISSION_ADT_EXPECTED_APS,
      expected_mission_ap_range: baseline[:expected_mission_ap_range] || LC_MISSION_ADT_AP_RANGE,
      expected_attack_ap: LC_ATTACK_ADT_AP,
      baseline_mission_actionpoints_observed: baseline_ok,
      baseline_attack_ap0_unused: ap0_was_unused,
      attack_replaced_mission_actionpoints: attack_shape_ok,
      runtime_sample_observed: sample_runtime,
      rts_exec_delta: rts_delta,
      passive_rts_exec_delta: passive_rts_delta,
      baseline_mission: baseline[:baseline_mission],
      baseline_ap0: baseline[:baseline_ap0],
      attack_shape: attack_shape,
      sample_effect: sample_effect,
      security_effect: reason
    }
  when :cf_config_table_disable_dequeue_and_reidentify
    attack_sync = cf_sync_config_table_with_engine_gate('attack_malicious_cf_config_engine_gate_sync')
    active_dump = dump_active_cf_config_table(10.0)
    active_table = active_dump[:parsed_table] || {}
    attack_trial = run_cf_dequeue_trial('attack_malicious_cf_dequeue_disabled_retains_pending_tx', 'attack')
    original_shape_ok = baseline[:original_table_shape_ok] == true
    malicious_shape_ok = baseline[:malicious_table_shape_ok] == true
    baseline_runtime_ok = baseline[:baseline_dequeue_processes_tx] == true
    active_table_malicious = active_table[:ok] && active_table[:local_eid].to_i == 125 && active_table[:channels].all? { |ch| ch[:dequeue_enabled].to_i == 0 }
    attack_runtime_ok = attack_trial[:tx_initiated] == true && attack_trial[:pending_queue_retained] == true && attack_trial[:sent_pdu_delta].to_i == 0
    confirmed = original_shape_ok && malicious_shape_ok && baseline_runtime_ok && active_table_malicious && attack_runtime_ok
    reason = if confirmed
               'cf_active_config_disabled_dequeue_and_retained_pending_outgoing_transaction'
             elsif !original_shape_ok
               'cf_original_config_table_shape_not_observed'
             elsif !malicious_shape_ok
               'cf_attack_config_table_does_not_contain_expected_malicious_fields'
             elsif !baseline_runtime_ok
               'cf_original_dequeue_runtime_behavior_not_observed'
             elsif !active_table_malicious
               'cf_active_table_dump_did_not_show_malicious_config'
             else
               'cf_malicious_dequeue_disabled_runtime_effect_not_observed'
             end

    {
      required: true,
      confirmed: confirmed,
      kind: 'cf_config_table_disable_dequeue_and_reidentify',
      expected_original_local_eid: baseline[:expected_original_local_eid] || 24,
      expected_attack_local_eid: baseline[:expected_attack_local_eid] || 125,
      expected_original_dequeue_enabled: baseline[:expected_original_dequeue_enabled] || 1,
      expected_attack_dequeue_enabled: baseline[:expected_attack_dequeue_enabled] || 0,
      original_table_shape_ok: original_shape_ok,
      malicious_table_shape_ok: malicious_shape_ok,
      baseline_dequeue_processes_tx: baseline_runtime_ok,
      active_table_malicious: active_table_malicious,
      attack_dequeue_disabled_retained_pending_tx: attack_runtime_ok,
      original_table: baseline[:original_table],
      malicious_table: baseline[:malicious_table],
      baseline_sync: baseline[:baseline_sync],
      baseline_trial: baseline[:baseline_trial],
      attack_sync: attack_sync,
      active_dump: active_dump,
      attack_trial: attack_trial,
      validation_defense: 'CF_ValidateConfigTable rejects only zero ticks_per_second, misaligned rx_crc_calc_bytes_per_wakeup, and oversized outgoing_file_chunk_size. The SP004 table keeps those values valid, so validation is expected to pass.',
      runtime_gate_defense: 'CF_CheckTables applies table updates only while CF_AppData.engine.enabled is false; the verifier disables the engine, requests CF HK to run CFE_TBL_Manage/GetAddress, then re-enables the engine so the accepted malicious config affects CFDP processing.',
      security_effect: reason,
      security_meaning: 'CF.config_table controls CFDP identity and channel behavior. The malicious table changes local_eid from 24 to 125 and disables dequeue on both channels. Once CF accepts the table through its engine-disabled update gate, a legitimate CF_TX_FILE can be queued but channel 0 does not dequeue it for transmission, suppressing outgoing CFDP file transfer.'
    }
  when :to_config_disable_used_entries
    update_effect = wait_for_to_table_update(baseline[:baseline_hk] || {}, 10.0, 0.5)
    active_dump = dump_active_table_to_file(spec[:target_id], spec[:table_name], TO_CONFIG_DUMP_TBL, 10.0)
    active_table = active_dump[:parsed_table] || {}
    baseline_ok = baseline[:baseline_to_hk_observed] == true
    original_table_enabled = baseline[:original_table_enabled] == true
    malicious_table_disables_used_entries = baseline[:malicious_table_disables_used_entries] == true
    table_updated = update_effect[:table_update_delta].to_i > 0
    table_update_errors_absent = update_effect[:tbl_err_delta].to_i <= 0
    active_dump_created = active_dump.dig(:dumped_file, :matched) == true && active_table[:ok]
    active_table_disabled = active_table[:used_count].to_i > 0 && active_table[:enabled_used_count].to_i == 0
    confirmed = baseline_ok && original_table_enabled && malicious_table_disables_used_entries &&
                table_updated && table_update_errors_absent && active_dump_created && active_table_disabled
    reason = if confirmed
               'to_active_config_used_entries_disabled_by_attacker_table'
             elsif !baseline_ok
               'to_hk_not_observed_before_attack'
             elsif !original_table_enabled
               'to_restore_table_not_a_clean_enabled_baseline'
             elsif !malicious_table_disables_used_entries
               'to_attack_table_does_not_disable_used_entries'
             elsif !table_updated
               'to_table_update_counter_did_not_increase_after_activation'
             elsif !table_update_errors_absent
               'to_table_error_counter_increased_after_activation'
             elsif !active_dump_created
               'to_active_table_dump_not_created_or_not_parseable'
             else
               'to_active_table_dump_did_not_show_disabled_used_entries'
             end

    {
      required: true,
      confirmed: confirmed,
      kind: 'to_config_disable_used_entries',
      expected_original_used_entries: baseline[:expected_original_used_entries],
      expected_attack_used_entries: baseline[:expected_attack_used_entries],
      expected_attack_entry_state: baseline[:expected_attack_entry_state] || 0,
      baseline_to_hk_observed: baseline_ok,
      original_table_enabled: original_table_enabled,
      malicious_table_disables_used_entries: malicious_table_disables_used_entries,
      to_table_update_observed: table_updated,
      to_table_update_errors_absent: table_update_errors_absent,
      active_dump_created: active_dump_created,
      active_table_used_entries_disabled: active_table_disabled,
      baseline_hk: baseline[:baseline_hk],
      original_table: baseline[:original_table],
      malicious_table: baseline[:malicious_table],
      update_effect: update_effect,
      active_dump: active_dump,
      security_effect: reason,
      security_meaning: 'TO.to_config is the telemetry output table. Current mission baseline keeps used entries enabled; the malicious table keeps the same telemetry MIDs but sets usState=0. TO_ProcessNewData only forwards a matched packet when usState is nonzero, so this active-table change suppresses those TO output entries when TO output routes are used.'
    }
  when :sc_rts001_ds_state_command_replaced
    attack_trial = run_sc_rts1_ds_state_trial('attack_malicious_rts1_disables_ds', DS_ENABLED, DS_DISABLED, 20.0)
    cleanup_command = set_ds_app_state(DS_ENABLED)
    cleanup_observed = wait_for_ds_app_state(DS_ENABLED, 8.0, 0.5)
    original_source_ok = baseline[:baseline_original_source_enables_ds] == true
    malicious_source_ok = baseline[:malicious_source_disables_ds] == true
    baseline_runtime_ok = baseline[:baseline_rts1_enables_ds] == true
    attack_runtime_ok = attack_trial[:confirmed] == true
    cleanup_ok = cleanup_observed[:matched] == true
    confirmed = original_source_ok && malicious_source_ok && baseline_runtime_ok && attack_runtime_ok
    reason = if confirmed
               'sc_rts001_authorized_trigger_disabled_ds_after_table_tamper'
             elsif !original_source_ok
               'sc_original_rts001_source_does_not_enable_ds_or_not_observed'
             elsif !malicious_source_ok
               'sc_attack_rts001_source_does_not_disable_ds'
             elsif !baseline_runtime_ok
               'sc_original_rts001_runtime_did_not_enable_ds'
             else
               'sc_malicious_rts001_runtime_did_not_disable_ds'
             end

    {
      required: true,
      confirmed: confirmed,
      kind: 'sc_rts001_ds_state_command_replaced',
      expected_original_ds_state_command: baseline[:expected_original_ds_state_command] || DS_ENABLED,
      expected_attack_ds_state_command: baseline[:expected_attack_ds_state_command] || DS_DISABLED,
      original_source_enables_ds: original_source_ok,
      malicious_source_disables_ds: malicious_source_ok,
      baseline_rts1_enables_ds: baseline_runtime_ok,
      attack_rts1_disables_ds: attack_runtime_ok,
      cleanup_ds_enabled: cleanup_ok,
      original_table_source: baseline[:original_table_source],
      malicious_table_source: baseline[:malicious_table_source],
      baseline_trial: baseline[:baseline_trial],
      attack_trial: attack_trial,
      cleanup_command: cleanup_command,
      cleanup_observed: cleanup_observed,
      security_effect: reason,
      security_meaning: 'SC.RTS_TBL001 is RTS #1, a stored command sequence used during startup/mode initialization. The original first command enables DS; the malicious table changes that command to disable DS. After tampering, a legitimate SC_START_RTS for RTS #1 causes DS HK APPENABLESTATE to become 0, so onboard data storage is suppressed.'
    }
  when :sc_ats1_first_command_reset_instead_of_noop
    attack_trial = run_sc_ats1_first_command_trial('attack_malicious_ats1_first_command_resets_counters', true, 45.0)
    original_source_ok = baseline[:baseline_original_source_noop] == true
    malicious_source_ok = baseline[:malicious_source_resets_counters] == true
    baseline_runtime_ok = baseline[:baseline_ats1_runs_noop_without_reset] == true
    attack_runtime_ok = attack_trial[:confirmed] == true
    confirmed = original_source_ok && malicious_source_ok && baseline_runtime_ok && attack_runtime_ok
    reason = if confirmed
               'sc_ats1_authorized_start_executed_attacker_replaced_reset_counters_command'
             elsif !original_source_ok
               'sc_original_ats1_source_first_command_not_noop_or_not_observed'
             elsif !malicious_source_ok
               'sc_attack_ats1_source_first_command_not_reset_counters'
             elsif !baseline_runtime_ok
               'sc_original_ats1_runtime_noop_effect_not_observed'
             else
               'sc_malicious_ats1_runtime_reset_counters_effect_not_observed'
             end

    {
      required: true,
      confirmed: confirmed,
      kind: 'sc_ats1_first_command_reset_instead_of_noop',
      expected_original_first_command: baseline[:expected_original_first_command] || 'SC_NOOP_CC',
      expected_attack_first_command: baseline[:expected_attack_first_command] || 'SC_RESET_COUNTERS_CC',
      original_source_noop: original_source_ok,
      malicious_source_resets_counters: malicious_source_ok,
      baseline_ats1_runs_noop_without_reset: baseline_runtime_ok,
      attack_ats1_resets_counters: attack_runtime_ok,
      original_table_source: baseline[:original_table_source],
      malicious_table_source: baseline[:malicious_table_source],
      baseline_trial: baseline[:baseline_trial],
      attack_trial: attack_trial,
      security_effect: reason,
      security_meaning: 'SC.ATS_TBL1 is Stored Command ATS A, an absolute-time command sequence. The NOS3 sample table first runs SC_NOOP at SC_TEST_TIME+30, then later enables/starts RTS1. The malicious table changes only command #1 to SC_RESET_COUNTERS_CC. After tampering, a legitimate SC_START_ATS for ATS A executes Reset Counters at that scheduled time, clearing SC housekeeping counters and altering the authorized stored-command timeline.'
    }
  when :sch_schedule_activity_suppression
    attack_sample = sample_sch_activity_window(10.0, 1.0)
    baseline_ok = baseline[:baseline_activity_observed] == true
    suppressed = sch_activity_suppressed?(attack_sample)
    {
      required: true,
      confirmed: baseline_ok && suppressed,
      kind: 'sch_schedule_activity_suppression',
      baseline_activity_observed: baseline_ok,
      attack_activity_suppressed: suppressed,
      baseline_sample: baseline[:baseline_sample],
      attack_sample: attack_sample,
      security_effect: baseline_ok && suppressed ?
        'sch_schedule_table_disabled_periodic_activities' :
        'sch_periodic_activity_suppression_not_observed'
    }
  when :sch_message_hijack_sch_hk_to_evs_hk
    attack_diag = wait_for_sch_diag_entry_msgid(CFE_EVS_SEND_HK_MID, baseline[:schedule_table_index] || 245, 16.0, 1.0)
    attack_sample = sample_sch_automatic_hk_window(12.0, 1.0)
    baseline_diag_ok = baseline[:baseline_diag_matches_sch_hk] == true
    attack_diag_hijacked = attack_diag[:msgid].to_i == CFE_EVS_SEND_HK_MID
    sch_still_active = attack_sample[:schedule_activity_success_delta_after_manual_refresh].to_i > 0 &&
                       attack_sample[:slots_processed_delta_after_manual_refresh].to_i > 0
    {
      required: true,
      confirmed: baseline_diag_ok && attack_diag_hijacked && sch_still_active,
      kind: 'sch_message_hijack_sch_hk_to_evs_hk',
      schedule_table_index: baseline[:schedule_table_index] || 245,
      diag_item: baseline[:diag_item] || sch_diag_msgid_item(245),
      baseline_diag_matches_sch_hk: baseline_diag_ok,
      attack_diag_matches_evs_hk: attack_diag_hijacked,
      sch_still_processing_activities: sch_still_active,
      baseline_diag: baseline[:baseline_diag],
      attack_diag: attack_diag,
      baseline_sample: baseline[:baseline_sample],
      attack_sample: attack_sample,
      automatic_sch_hk_suppressed_while_sch_active: sch_automatic_hk_hijacked?(attack_sample),
      security_effect: baseline_diag_ok && attack_diag_hijacked && sch_still_active ?
        'sch_message_definition_hijacked_schedule_entry_245_from_sch_hk_to_evs_hk' :
        'sch_message_definition_hijack_effect_not_observed'
    }
  else
    {
      required: true,
      confirmed: false,
      kind: 'no_profile_specific_effect_check_defined',
      security_effect: 'verifier_has_no_runtime_effect_check_for_profile'
    }
  end
end

def read_tbl_safe(refresh = true)
  read_tbl(refresh: refresh)
rescue Exception => error
  { error_class: error.class.to_s, error: error.message }
end

def collect_events_and_tbl(timeout_seconds, table_name: nil, mode: nil, before_tbl: nil, interval: 0.2)
  deadline = Time.now + timeout_seconds
  last_owner_hk_request = Time.at(0)
  events = []
  errors = []
  last_seq = nil
  last_state = nil
  matched = false
  success = false
  failure = false
  reason = nil

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

    last_state = read_tbl_safe

    if table_name && [:validate, :activate].include?(mode) && (Time.now - last_owner_hk_request) >= 1.0
      request_table_owner_hk(table_name)
      last_owner_hk_request = Time.now
    end

    if table_name
      if event_text_matches?({ events: events }, table_event_patterns(table_name, :missing))
        matched = true
        failure = true
        reason = 'table_not_registered'
        break
      end

      case mode
      when :validate
        success_by_event = event_text_matches?({ events: events }, table_event_patterns(table_name, :validated))
        success_by_hk = tbl_state_mentions?(last_state, :last_val_table_name, table_name) &&
                        before_tbl.is_a?(Hash) &&
                        last_state.fetch(:success_val_count, -1).to_i > before_tbl.fetch(:success_val_count, -1).to_i &&
                        last_state.fetch(:last_val_status, -1).to_i == 0
        failure_by_event = event_text_matches?({ events: events }, [/Too many Table Validations have been requested/i, /Validation.*#{Regexp.escape(table_name)}.*failed/i])
        failure_by_hk = tbl_state_mentions?(last_state, :last_val_table_name, table_name) &&
                        before_tbl.is_a?(Hash) &&
                        last_state.fetch(:failed_val_count, -1).to_i > before_tbl.fetch(:failed_val_count, -1).to_i
        if success_by_event || success_by_hk
          matched = true
          success = true
          reason = success_by_event ? 'validation_success_event' : 'validation_success_tbl_hk'
          break
        elsif failure_by_event || failure_by_hk
          matched = true
          failure = true
          reason = failure_by_event ? 'validation_failed_event' : 'validation_failed_tbl_hk'
          break
        end
      when :activate
        success_by_event = event_text_matches?({ events: events }, table_event_patterns(table_name, :activated))
        before_pending = before_tbl.is_a?(Hash) ? before_tbl.fetch(:num_load_pending, nil) : nil
        after_pending = last_state.is_a?(Hash) ? last_state.fetch(:num_load_pending, nil) : nil
        pending_decreased = !before_pending.nil? && !after_pending.nil? && after_pending.to_i < before_pending.to_i
        pending_clear = !after_pending.nil? && after_pending.to_i == 0
        success_by_hk = tbl_state_mentions?(last_state, :last_updated_tbl, table_name) &&
                        before_tbl.is_a?(Hash) &&
                        last_state.fetch(:cmd_count, -1).to_i > before_tbl.fetch(:cmd_count, -1).to_i &&
                        (pending_decreased || pending_clear)
        err_increased = before_tbl.is_a?(Hash) && last_state.fetch(:err_count, 0).to_i > before_tbl.fetch(:err_count, 0).to_i
        failure_by_event = event_text_matches?({ events: events }, [/Cannot activate table '#{Regexp.escape(table_name)}'/i,
                                                                     /No Inactive Buffer for Table '#{Regexp.escape(table_name)}'/i,
                                                                     /Inactive image.*#{Regexp.escape(table_name)}.*not Validated/i])
        if success_by_event || (success_by_hk && !err_increased)
          matched = true
          success = true
          reason = success_by_event ? 'activation_success_event' : 'activation_success_tbl_hk'
          break
        elsif failure_by_event || (err_increased && before_tbl.is_a?(Hash) && last_state.fetch(:cmd_count, -1).to_i > before_tbl.fetch(:cmd_count, -1).to_i)
          matched = true
          failure = true
          reason = failure_by_event ? 'activation_failed_event' : 'activation_error_counter_increased'
          break
        end
      when :load
        success_by_event = event_text_matches?({ events: events }, [/Successful load of .* into '#{Regexp.escape(table_name)}' working buffer/i])
        failure_by_event = event_text_matches?({ events: events }, [/No working buffers available for table '#{Regexp.escape(table_name)}'/i, /Attempted to load table '#{Regexp.escape(table_name)}' while previous load is still pending/i, /Unable to locate '#{Regexp.escape(table_name)}'/i])
        success_by_hk = before_tbl.is_a?(Hash) && last_state.is_a?(Hash) &&
                        last_state.fetch(:cmd_count, -1).to_i > before_tbl.fetch(:cmd_count, -1).to_i &&
                        last_state.fetch(:err_count, 0).to_i == before_tbl.fetch(:err_count, 0).to_i
        if success_by_event || success_by_hk
          matched = true
          success = true
          reason = success_by_event ? 'load_success_event' : 'load_success_tbl_hk'
          break
        elsif failure_by_event
          matched = true
          failure = true
          reason = 'load_failed_event'
          break
        end
      end
    end

    sleep(interval)
  end

  { matched: matched, success: success, failure: failure, reason: reason || 'timeout', events: events, errors: errors, last_state: last_state }
end

def abort_table_load(target_id, table_name)
  before = read_tbl_safe
  command = sp004_run_profile(SP004_PROFILE_TBL_ABORT_LOAD, target_id, table_name: table_name)
  observed = collect_events_and_tbl(2.5, table_name: table_name, mode: nil, before_tbl: before)
  { command: command, before: before, observed: observed, after: read_tbl_safe }
end

def wait_tbl_load_pending_clear(timeout_seconds = 8.0, interval = 0.45)
  deadline = Time.now + timeout_seconds
  states = []
  last_state = nil

  until Time.now >= deadline
    last_state = read_tbl_safe
    states << last_state if states.length < 8
    if last_state.is_a?(Hash) && last_state.fetch(:num_load_pending, 0).to_i == 0
      return { cleared: true, reason: 'num_load_pending_zero', states: states, last_state: last_state }
    end
    sleep(interval)
  end

  { cleared: false, reason: 'timeout_waiting_num_load_pending_zero', states: states, last_state: last_state }
end

def observed_file_loaded?(cycle, cf_path, table_name = nil)
  base = File.basename(cf_path)
  patterns = ["Successful load of '#{cf_path}'"]
  patterns << "Successful load of '#{cf_path}' into '#{table_name}'" if table_name
  event_sources = [cycle[:load_events], cycle[:validate_events], cycle[:activate_events], cycle[:events], cycle.dig(:load_wait, :events)].compact

  event_sources.any? do |events|
    event_text_matches?(events, patterns) || (event_text_matches?(events, [base]) && event_text_matches?(events, ["Successful load"]))
  end
end

def observed_table_validated?(cycle, table_name)
  event_sources = [cycle[:validate_events], cycle[:activate_events], cycle[:events], cycle.dig(:validate_wait, :events)].compact
  event_hit = event_sources.any? { |events| event_text_matches?(events, table_event_patterns(table_name, :validated)) }
  hk_hit = [cycle.dig(:validate_wait, :last_state), cycle[:validate_state], cycle[:activate_state], cycle[:tbl_state]].compact.any? do |state|
    tbl_state_mentions?(state, :last_val_table_name, table_name) && state.fetch(:last_val_status, -1).to_i == 0
  end
  event_hit || hk_hit || cycle.dig(:validate_wait, :success) == true
end

def pending_clear_activated?(pending_clear, table_name)
  return false unless pending_clear.is_a?(Hash) && pending_clear[:cleared]

  states = [pending_clear[:last_state], *pending_clear.fetch(:states, [])].compact
  states.any? { |state| tbl_state_mentions?(state, :last_updated_tbl, table_name) }
end

def observed_table_activated?(cycle, table_name)
  event_sources = [cycle[:activate_events], cycle[:events], cycle.dig(:activate_wait, :events), cycle.dig(:abort_cleanup, :observed, :events)].compact
  event_hit = event_sources.any? { |events| event_text_matches?(events, table_event_patterns(table_name, :activated)) }
  hk_hit = cycle.dig(:activate_wait, :success) == true &&
           tbl_state_mentions?(cycle.dig(:activate_wait, :last_state), :last_updated_tbl, table_name)
  event_hit || hk_hit || pending_clear_activated?(cycle[:pending_clear], table_name)
end

def cycle_failure_reason(cycle)
  waits = [cycle[:load_wait], cycle[:validate_wait], cycle[:activate_wait]].compact
  wait_reason = waits.find { |wait| wait[:failure] }&.fetch(:reason, nil)
  return wait_reason if wait_reason

  waits.find { |wait| wait[:matched] == false }&.fetch(:reason, nil)
end

def run_table_cycle(target_id, use_restore, label, table_name, step_delay_ms = 450)
  load_flags = use_restore ? SP004_FLAG_USE_RESTORE_FILE : 0

  quiet_before = read_tbl_safe
  load_before = read_tbl_safe
  load = sp004_run_profile(SP004_PROFILE_TBL_LOAD, target_id, flags: load_flags, step_delay_ms: step_delay_ms)
  load_wait = collect_events_and_tbl(6.0, table_name: table_name, mode: :load, before_tbl: load_before)
  load_events = { events: load_wait[:events], errors: load_wait[:errors] }
  load_state = read_tbl_safe

  validate = nil
  validate_wait = { matched: false, success: false, failure: false, reason: 'not_attempted_load_not_confirmed', events: [], errors: [], last_state: load_state }
  validate_before = read_tbl_safe
  validate_events = { events: [], errors: [] }
  validate_state = validate_before

  activate = nil
  activate_wait = { matched: false, success: false, failure: false, reason: 'not_attempted_validation_not_confirmed', events: [], errors: [], last_state: validate_state }
  activate_before = read_tbl_safe
  activate_events = { events: [], errors: [] }
  activate_state = activate_before
  pending_clear = { cleared: false, reason: 'not_attempted_activation_not_confirmed', states: [], last_state: activate_before }
  abort_cleanup = nil

  if load_wait[:success]
    validate_before = read_tbl_safe
    validate = sp004_run_profile(SP004_PROFILE_TBL_VALIDATE_INACTIVE, target_id, step_delay_ms: step_delay_ms)
    validate_wait = collect_events_and_tbl(22.0, table_name: table_name, mode: :validate, before_tbl: validate_before)
    validate_events = { events: validate_wait[:events], errors: validate_wait[:errors] }
    validate_state = read_tbl_safe
  end

  if validate_wait[:success]
    activate_before = read_tbl_safe
    activate = sp004_run_profile(SP004_PROFILE_TBL_ACTIVATE, target_id, step_delay_ms: step_delay_ms)
    activate_wait = collect_events_and_tbl(10.0, table_name: table_name, mode: :activate, before_tbl: activate_before)
    activate_events = { events: activate_wait[:events], errors: activate_wait[:errors] }
    pending_clear = wait_tbl_load_pending_clear(8.0)
    if pending_clear_activated?(pending_clear, table_name)
      activate_wait = activate_wait.merge(
        matched: true,
        success: true,
        failure: false,
        reason: 'activation_success_pending_clear_tbl_hk',
        last_state: pending_clear[:last_state]
      )
    end
    activate_state = read_tbl_safe

    unless activate_wait[:success] && pending_clear[:cleared]
      abort_cleanup = abort_table_load(target_id, table_name)
      pending_clear = wait_tbl_load_pending_clear(4.0) unless pending_clear[:cleared]
    end
  else
    abort_cleanup = abort_table_load(target_id, table_name)
    pending_clear = wait_tbl_load_pending_clear(4.0)
  end

  {
    label: label,
    use_restore: use_restore,
    quiet_before: quiet_before,
    load: load,
    validate: validate || { ok: false, skipped: true, reason: validate_wait[:reason] },
    activate: activate || { ok: false, skipped: true, reason: activate_wait[:reason] },
    load_before: load_before,
    validate_before: validate_before,
    activate_before: activate_before,
    load_wait: load_wait,
    validate_wait: validate_wait,
    activate_wait: activate_wait,
    abort_cleanup: abort_cleanup,
    pending_clear: pending_clear,
    load_events: load_events,
    validate_events: validate_events,
    activate_events: activate_events,
    load_state: load_state,
    validate_state: validate_state,
    activate_state: activate_state,
    tbl_state: read_tbl_safe
  }
end

def table_tamper_specs
  [
    {
      profile_id: 'ds_file_table_redirect_storage',
      name: 'DS.FILE_TBL tamper: redirect DS destination files and rollover policy',
      risk: 'safe',
      target: 'DS.FILE_TBL',
      target_id: SP004_TARGET_DS_FILE,
      table_name: 'DS.FILE_TBL',
      attack_tbl: '/cf/sp004_ds_file.tbl',
      restore_tbl: '/cf/ds_file_tbl.tbl',
      effect_check: :ds_malicious_output_files,
      consequence: 'DS destination file routing can be changed to a small attacker-selected /cf file.'
    },
    {
      profile_id: 'ds_filter_table_mid_capture',
      name: 'DS.FILTER_TBL tamper: alter recorded MIDs and sampling rules',
      risk: 'safe',
      target: 'DS.FILTER_TBL',
      target_id: SP004_TARGET_DS_FILTER,
      table_name: 'DS.FILTER_TBL',
      attack_tbl: '/cf/sp004_ds_filter.tbl',
      restore_tbl: '/cf/ds_filter_tbl.tbl',
      effect_check: :ds_filter_es_hk_to_file_index_zero,
      consequence: 'DS packet filtering can be redirected to capture selected cFE event/HK packets.'
    },
    {
      profile_id: 'lc_watchpoint_table_threshold_tamper',
      name: 'LC.LC_WDT tamper: change watchpoint MID, offset, comparison and threshold',
      risk: 'safe',
      target: 'LC.LC_WDT',
      target_id: SP004_TARGET_LC_WDT,
      table_name: 'LC.LC_WDT',
      attack_tbl: '/cf/sp004_lc_wdt.tbl',
      restore_tbl: '/cf/lc_def_wdt.tbl',
      effect_check: :lc_wdt_replace_mission_watchpoints_with_es_hk_true,
      consequence: 'LC mission watchpoints can be replaced with an attacker-selected ES HK always-true watchpoint.'
    },
    {
      profile_id: 'lc_actionpoint_table_rts_tamper',
      name: 'LC.LC_ADT tamper: change actionpoint state, RTS trigger and RPN logic',
      risk: 'safe',
      target: 'LC.LC_ADT',
      target_id: SP004_TARGET_LC_ADT,
      table_name: 'LC.LC_ADT',
      attack_tbl: '/cf/sp004_lc_adt.tbl',
      restore_tbl: '/cf/lc_def_adt.tbl',
      effect_check: :lc_adt_replace_mission_actionpoints_with_ap0_rts,
      consequence: 'LC mission actionpoints can be replaced by an attacker-selected AP #0 mapped to RTS 1.'
    },
    {
      profile_id: 'cf_config_table_channel_degrade',
      name: 'CF.config_table tamper: change CFDP channel, entity id, poll/dequeue settings',
      risk: 'safe',
      target: 'CF.config_table',
      target_id: SP004_TARGET_CF_CONFIG,
      table_name: 'CF.config_table',
      attack_tbl: '/cf/sp004_cf_cfg.tbl',
      restore_tbl: '/cf/cf_def_config.tbl',
      effect_check: :cf_config_table_disable_dequeue_and_reidentify,
      consequence: 'CFDP channel dequeue and polling behavior can be disabled or degraded.'
    },
    {
      profile_id: 'to_config_table_disable_routes',
      name: 'TO.to_config tamper: change downlink routes, MID list, group and queue limits',
      risk: 'safe',
      target: 'TO.to_config',
      target_id: SP004_TARGET_TO_CONFIG,
      table_name: 'TO.to_config',
      attack_tbl: '/cf/sp004_to_cfg.tbl',
      restore_tbl: '/cf/to_config.tbl',
      effect_check: :to_config_disable_used_entries,
      consequence: 'TO telemetry output table entries can be disabled by a malicious active table, suppressing matched telemetry on TO output routes.'
    },
    {
      profile_id: 'sc_rts_table_disable_startup_sequence',
      name: 'SC.RTS_TBL001 tamper: alter stored RTS command sequence',
      risk: 'safe',
      target: 'SC.RTS_TBL001',
      target_id: SP004_TARGET_SC_RTS001,
      table_name: 'SC.RTS_TBL001',
      attack_tbl: '/cf/sp004_sc_rts1.tbl',
      restore_tbl: '/cf/sc_rts001.tbl',
      effect_check: :sc_rts001_ds_state_command_replaced,
      consequence: 'SC RTS001 can be changed so an authorized RTS trigger disables DS data storage instead of enabling it.'
    },
    {
      profile_id: 'sc_ats_table_command_sequence_tamper',
      name: 'SC.ATS_TBL1 tamper: alter absolute-time command sequence',
      risk: 'safe',
      target: 'SC.ATS_TBL1',
      target_id: SP004_TARGET_SC_ATS1,
      table_name: 'SC.ATS_TBL1',
      attack_tbl: '/cf/sp004_sc_ats1.tbl',
      restore_tbl: '/cf/sc_ats1.tbl',
      effect_check: :sc_ats1_first_command_reset_instead_of_noop,
      consequence: 'SC ATS1 content can be changed so timed command execution differs from the authorized plan.'
    },
    {
      profile_id: 'sch_schedule_table_disable_routine',
      name: 'SCH.SCHED_DEF tamper: disable/change scheduled HK and task wakeups',
      risk: 'safe',
      target: 'SCH.SCHED_DEF',
      target_id: SP004_TARGET_SCH_SCHED,
      table_name: 'SCH.SCHED_DEF',
      attack_tbl: '/cf/sp004_sch_sched.tbl',
      restore_tbl: '/cf/sch_def_schtbl.tbl',
      effect_check: :sch_schedule_activity_suppression,
      consequence: 'SCH schedule entries can be cleared, disrupting periodic housekeeping and task wakeups.'
    },
    {
      profile_id: 'sch_message_table_hijack_mid',
      name: 'SCH.MSG_DEFS tamper: redirect scheduled command MID/content',
      risk: 'safe',
      target: 'SCH.MSG_DEFS',
      target_id: SP004_TARGET_SCH_MSG,
      table_name: 'SCH.MSG_DEFS',
      attack_tbl: '/cf/sp004_sch_msg.tbl',
      restore_tbl: '/cf/sch_def_msgtbl.tbl',
      effect_check: :sch_message_hijack_sch_hk_to_evs_hk,
      consequence: 'SCH message definitions can be changed so an existing schedule entry sends a different command.'
    }
  ]
end

def run_table_cycle_for_spec(spec, use_restore, label)
  if spec[:effect_check] == :cf_config_table_disable_dequeue_and_reidentify
    gate = {
      disable_command: cf_disable_engine,
      disable_events: collect_events(1.5, 0.15),
      hk_manage_before_cycle: read_cf_hk(true)
    }
    cycle = run_table_cycle(spec[:target_id], use_restore, label, spec[:table_name])
    cycle[:cf_engine_gate_before_cycle] = gate
    cycle
  else
    run_table_cycle(spec[:target_id], use_restore, label, spec[:table_name])
  end
end

def run_generic_table_tamper(spec)
  unless File.exist?(APP_HOST_PATH)
    raise SkipProfile, "SP004 app shared object is missing: #{APP_HOST_PATH}. Run install, make config, and make fsw."
  end

  attack_host = host_cf_path(spec[:attack_tbl])
  restore_host = host_cf_path(spec[:restore_tbl])
  unless File.exist?(attack_host)
    raise SkipProfile, "SP004 attack table is missing: #{attack_host}. Run make fsw after install."
  end
  unless File.exist?(restore_host)
    raise SkipProfile, "Original restore table is missing: #{restore_host}."
  end

  before_tbl = read_tbl_safe
  pre_restore = run_table_cycle_for_spec(spec, true, 'pre_restore_original_table')
  attack_effect_baseline = capture_attack_effect_baseline(spec)
  attack = run_table_cycle_for_spec(spec, false, 'attack_load_malicious_table')
  attack_effect = observe_attack_effect(spec, attack_effect_baseline)
  restore = run_table_cycle_for_spec(spec, true, 'restore_original_table')
  post_restore_app_sync = spec[:effect_check] == :cf_config_table_disable_dequeue_and_reidentify ?
                            cf_sync_config_table_with_engine_gate('post_restore_original_cf_config_engine_gate_sync') : nil
  after_tbl = read_tbl_safe

  evidence = {
    sp004_so_present: File.exist?(APP_HOST_PATH),
    malicious_table_present: File.exist?(attack_host),
    restore_table_present: File.exist?(restore_host),
    pre_restore_command_chain_sent: pre_restore.dig(:load, :ok) && pre_restore.dig(:validate, :ok) && pre_restore.dig(:activate, :ok),
    attack_load_command_sent_via_ci_lab: attack.dig(:load, :ok),
    attack_validate_command_sent_via_ci_lab: attack.dig(:validate, :ok),
    attack_activate_command_sent_via_ci_lab: attack.dig(:activate, :ok),
    tbl_loaded_malicious_table: observed_file_loaded?(attack, spec[:attack_tbl], spec[:table_name]),
    tbl_validated_target_table: observed_table_validated?(attack, spec[:table_name]),
    tbl_activated_target_table: observed_table_activated?(attack, spec[:table_name]),
    post_attack_effect_check_required: attack_effect[:required],
    post_attack_effect_confirmed: attack_effect[:confirmed],
    restore_load_command_sent_via_ci_lab: restore.dig(:load, :ok),
    restore_validate_command_sent_via_ci_lab: restore.dig(:validate, :ok),
    restore_activate_command_sent_via_ci_lab: restore.dig(:activate, :ok),
    tbl_loaded_original_table: observed_file_loaded?(restore, spec[:restore_tbl], spec[:table_name]),
    tbl_restored_target_table: observed_table_activated?(restore, spec[:table_name])
  }
  evidence[:cf_post_restore_app_config_synced] = post_restore_app_sync[:confirmed] if post_restore_app_sync

  success = evidence[:sp004_so_present] && evidence[:malicious_table_present] && evidence[:restore_table_present] &&
            evidence[:attack_load_command_sent_via_ci_lab] && evidence[:attack_validate_command_sent_via_ci_lab] &&
            evidence[:attack_activate_command_sent_via_ci_lab] && evidence[:tbl_validated_target_table] &&
            evidence[:tbl_activated_target_table] && evidence[:post_attack_effect_confirmed] &&
            evidence[:restore_validate_command_sent_via_ci_lab] && evidence[:restore_activate_command_sent_via_ci_lab] &&
            evidence[:tbl_restored_target_table]
  table_not_registered = [pre_restore, attack, restore].any? do |cycle|
    [cycle[:load_events], cycle[:validate_events], cycle[:activate_events], cycle[:events]].compact.any? do |events|
      events_include_any?(events, ["Unable to locate '#{spec[:table_name]}' in Table Registry"])
    end
  end
  evidence[:target_table_registered_in_current_mission] = !table_not_registered

  verdict =
    if table_not_registered
      'not_applicable_table_not_registered_in_current_mission'
    elsif success && spec[:startup_only]
      'attack_success_table_accepted_startup_effect_requires_restart'
    elsif success && spec[:multinode_effect_not_checked]
      'attack_success_table_accepted_multinode_effect_not_checked'
    elsif success
      'attack_success'
    elsif cycle_failure_reason(attack) == 'table_not_registered'
      'not_applicable_table_not_registered_in_current_mission'
    elsif cycle_failure_reason(attack).to_s.include?('load_failed') || cycle_failure_reason(attack).to_s.include?('no_working')
      'payload_not_loaded_or_no_working_buffer'
    elsif !evidence[:tbl_validated_target_table]
      'target_validation_not_confirmed_or_rejected'
    elsif evidence[:tbl_validated_target_table] && !evidence[:tbl_activated_target_table]
      'target_activation_not_confirmed_or_rejected'
    elsif evidence[:post_attack_effect_check_required] && !evidence[:post_attack_effect_confirmed]
      attack_effect[:kind] == 'no_profile_specific_effect_check_defined' ?
        'verifier_runtime_effect_check_not_implemented' :
        'target_table_updated_but_runtime_attack_effect_not_observed'
    elsif !evidence[:tbl_restored_target_table]
      'restore_not_confirmed'
    else
      'inconclusive_table_effect_not_confirmed'
    end

  status = table_not_registered ? 'SKIP' : (success ? 'PASS' : 'FAIL')
  verdict_score(status, verdict, evidence,
                consequence: spec[:consequence], startup_only: spec.fetch(:startup_only, false),
                multinode_effect_not_checked: spec.fetch(:multinode_effect_not_checked, false),
                before_tbl: before_tbl, pre_restore: pre_restore, attack: attack,
                attack_effect_baseline: attack_effect_baseline, attack_effect: attack_effect, restore: restore,
                post_restore_app_sync: post_restore_app_sync,
                after_tbl: after_tbl, sp004_hk_optional: read_sp004_optional)
end


def run_fm_table_cycle(use_restore, label)
  cycle = run_table_cycle(SP004_TARGET_FM_MONITOR, use_restore, label, 'FM.FreeSpace', 3000)
  cycle[:fm_good_entries] = fm_verify_good_entries(cycle[:events])
  cycle
end


def run_registry_disclosure
  before_tbl = read_tbl
  remove_file(TBL_REGISTRY_DUMP_HOST_PATH)
  send_registry = sp004_run_profile(
    SP004_PROFILE_TBL_SEND_REGISTRY,
    SP004_TARGET_CUSTOM,
    table_name: 'SCH.SCHED_DEF'
  )
  send_registry_events = collect_events(3.0)

  dump_registry = sp004_run_profile(
    SP004_PROFILE_TBL_DUMP_REGISTRY,
    SP004_TARGET_CUSTOM,
    dump_filename: TBL_REGISTRY_DUMP
  )
  dump_events = collect_events(5.0)
  dumped_file = wait_for_file(TBL_REGISTRY_DUMP_HOST_PATH, 10.0)
  after_tbl = read_tbl

  evidence = {
    send_registry_command_sent_via_ci_lab: send_registry[:ok],
    registry_telemetry_command_observed: events_include_any?(send_registry_events, ['SCH.SCHED_DEF']) || read_tbl_registry_safe[:name] == 'SCH.SCHED_DEF',
    dump_registry_command_sent_via_ci_lab: dump_registry[:ok],
    registry_dump_file_created: dumped_file[:matched],
    registry_dump_file_nonempty: dumped_file[:size].to_i.positive?,
    registry_dump_discloses_real_table: file_contains?(TBL_REGISTRY_DUMP_HOST_PATH, 'SCH.SCHED_DEF') ||
                                        file_contains?(TBL_REGISTRY_DUMP_HOST_PATH, 'FM.FreeSpace') ||
                                        file_contains?(TBL_REGISTRY_DUMP_HOST_PATH, 'DS.FILE_TBL')
  }
  success = evidence[:dump_registry_command_sent_via_ci_lab] && evidence[:registry_dump_file_created] &&
            evidence[:registry_dump_file_nonempty] && evidence[:registry_dump_discloses_real_table]

  verdict_score(success ? 'PASS' : 'FAIL', success ? 'attack_success' : 'inconclusive_no_registry_dump_disclosure',
                evidence, before_tbl: before_tbl, after_tbl: after_tbl, send_registry: send_registry,
                send_registry_events: send_registry_events, dump_registry: dump_registry,
                dump_events: dump_events, dumped_file: dumped_file)
end


def run_fm_monitor_disable_all
  unless File.exist?(APP_HOST_PATH)
    raise SkipProfile, "SP004 app shared object is missing: #{APP_HOST_PATH}. Run install, make config, and make fsw."
  end
  unless File.exist?(FM_BAD_TBL_HOST_PATH)
    raise SkipProfile, "SP004 FM attack table is missing: #{FM_BAD_TBL_HOST_PATH}. Run make fsw after install."
  end

  before_tbl = read_tbl
  pre_restore = run_fm_table_cycle(true, 'pre_restore_original_fm_table')
  baseline_free_space = fm_free_space_packet(4.0)

  attack = run_fm_table_cycle(false, 'attack_load_bad_fm_table')
  after_attack_free_space = fm_free_space_packet(4.0)

  restore = run_fm_table_cycle(true, 'restore_original_fm_table')
  after_restore_free_space = fm_free_space_packet(4.0)

  attack_load_observed = observed_file_loaded?(attack, FM_BAD_TBL, 'FM.FreeSpace')
  attack_validate_observed = observed_table_validated?(attack, 'FM.FreeSpace') || attack[:fm_good_entries].include?(0)
  attack_activate_observed = observed_table_activated?(attack, 'FM.FreeSpace')
  restore_load_observed = observed_file_loaded?(restore, FM_RESTORE_TBL, 'FM.FreeSpace')
  restore_validate_observed = observed_table_validated?(restore, 'FM.FreeSpace') ||
                              restore[:fm_good_entries].any? { |value| value.positive? }
  restore_activate_observed = observed_table_activated?(restore, 'FM.FreeSpace')

  baseline_names = fm_present_names(baseline_free_space)
  attack_names = fm_present_names(after_attack_free_space)
  restore_names = fm_present_names(after_restore_free_space)
  baseline_original_observed = fm_monitor_report_has_content?(baseline_free_space)
  attack_all_cleared = fm_monitor_report_all_zero?(after_attack_free_space)
  restore_original_observed = fm_monitor_report_has_content?(after_restore_free_space)
  baseline_signature_words = fm_report_signature_words(baseline_free_space)
  attack_signature_words = fm_report_signature_words(after_attack_free_space)
  restore_signature_words = fm_report_signature_words(after_restore_free_space)

  evidence = {
    sp004_so_present: File.exist?(APP_HOST_PATH),
    malicious_fm_table_present: File.exist?(FM_BAD_TBL_HOST_PATH),
    restore_fm_table_present: File.exist?(host_cf_path(FM_RESTORE_TBL)),
    pre_restore_command_chain_sent: pre_restore.dig(:load, :ok) && pre_restore.dig(:validate, :ok) && pre_restore.dig(:activate, :ok),
    fm_baseline_free_space_packet_received: baseline_free_space[:matched] == true,
    fm_baseline_names: baseline_names,
    fm_baseline_signature_words: baseline_signature_words,
    fm_baseline_monitor_report_has_content: baseline_original_observed,
    attack_load_command_sent_via_ci_lab: attack.dig(:load, :ok),
    attack_validate_command_sent_via_ci_lab: attack.dig(:validate, :ok),
    attack_activate_command_sent_via_ci_lab: attack.dig(:activate, :ok),
    tbl_loaded_malicious_fm_table: attack_load_observed,
    tbl_validated_fm_table: attack_validate_observed,
    tbl_activated_fm_table: attack_activate_observed,
    fm_after_attack_free_space_packet_received: after_attack_free_space[:matched] == true,
    fm_after_attack_names: attack_names,
    fm_after_attack_signature_words: attack_signature_words,
    fm_after_attack_monitor_report_all_zero: attack_all_cleared,
    restore_load_command_sent_via_ci_lab: restore.dig(:load, :ok),
    restore_validate_command_sent_via_ci_lab: restore.dig(:validate, :ok),
    restore_activate_command_sent_via_ci_lab: restore.dig(:activate, :ok),
    tbl_loaded_original_fm_table: restore_load_observed,
    tbl_validated_original_fm_table: restore_validate_observed,
    tbl_activated_original_fm_table: restore_activate_observed,
    fm_after_restore_free_space_packet_received: after_restore_free_space[:matched] == true,
    fm_after_restore_names: restore_names,
    fm_after_restore_signature_words: restore_signature_words,
    fm_after_restore_monitor_report_has_content: restore_original_observed
  }

  success = evidence[:sp004_so_present] && evidence[:malicious_fm_table_present] && evidence[:restore_fm_table_present] &&
            evidence[:pre_restore_command_chain_sent] && evidence[:fm_baseline_monitor_report_has_content] &&
            evidence[:attack_load_command_sent_via_ci_lab] && evidence[:attack_validate_command_sent_via_ci_lab] &&
            evidence[:attack_activate_command_sent_via_ci_lab] && evidence[:tbl_validated_fm_table] &&
            evidence[:tbl_activated_fm_table] && evidence[:fm_after_attack_monitor_report_all_zero] &&
            evidence[:restore_validate_command_sent_via_ci_lab] && evidence[:restore_activate_command_sent_via_ci_lab] &&
            evidence[:tbl_activated_original_fm_table] && evidence[:fm_after_restore_monitor_report_has_content]
  verdict =
    if success
      'attack_success'
    elsif attack_load_observed && attack_validate_observed && !attack_activate_observed
      'target_activation_not_confirmed_or_rejected'
    elsif attack_activate_observed && !baseline_original_observed
      'baseline_fm_free_space_telemetry_content_not_observed'
    elsif attack_activate_observed && !attack_all_cleared
      'target_table_updated_but_fm_free_space_telemetry_not_cleared'
    elsif !restore_activate_observed || !restore_original_observed
      'restore_not_confirmed'
    else
      'inconclusive_payload_not_confirmed'
    end

  verdict_score(success ? 'PASS' : 'FAIL', verdict, evidence,
                before_tbl: before_tbl, pre_restore: pre_restore, attack: attack, restore: restore,
                baseline_free_space: baseline_free_space, after_attack_free_space: after_attack_free_space,
                after_restore_free_space: after_restore_free_space, sp004_hk_optional: read_sp004_optional)
end



def run_noop_baseline
  start = start_sp004
  before_hk = read_sp004_optional
  noop = send_udp(command_packet(SP004_CMD_MID, 0, ''.b))
  noop_events = collect_events(3.0)
  hk_wait = wait_sp004_cmd_counter_increment(before_hk, 4.0)
  query = query_one_app(APP_NAME)
  evidence = {
    sp004_app_started_or_alive: start[:ok],
    noop_sent_via_ci_lab: noop[:ok],
    sp004_noop_event_observed: events_include?(noop_events, 'SP004: NOOP command received'),
    sp004_hk_counter_incremented_after_noop: hk_wait[:matched],
    es_reports_sp004_app: query[:ok]
  }
  success = evidence[:sp004_app_started_or_alive] && evidence[:noop_sent_via_ci_lab] &&
            (evidence[:sp004_noop_event_observed] || evidence[:sp004_hk_counter_incremented_after_noop]) &&
            evidence[:es_reports_sp004_app]
  verdict_score(success ? 'PASS' : 'FAIL', success ? 'attack_success' : 'preflight_failed_sp004_not_receiving_commands',
                evidence, start: start, before_hk: before_hk, noop: noop, noop_events: noop_events,
                hk_wait: hk_wait, query: query, sp004_hk_optional: read_sp004_optional)
end

def profile_definitions
  base_profiles = [
    {
      profile_id: 'sp004_noop_baseline',
      name: 'Baseline: SP004 app loaded by ES and receiving CI_LAB commands',
      risk: 'safe',
      target: 'SP004',
      run: method(:run_noop_baseline)
    },
    {
      profile_id: 'tbl_registry_dump_disclosure',
      name: 'Malicious app discloses cFE Table Registry via TBL services',
      risk: 'safe',
      target: 'CFE_TBL',
      run: method(:run_registry_disclosure)
    },
    {
      profile_id: 'fm_freespace_table_disable_all',
      name: 'FM.FreeSpace tamper: hide or falsify monitored filesystem state',
      risk: 'safe',
      target: 'FM.FreeSpace',
      run: method(:run_fm_monitor_disable_all)
    }
  ]

  table_tamper_specs.each do |spec|
    base_profiles << {
      profile_id: spec[:profile_id],
      name: spec[:name],
      risk: spec[:risk],
      target: spec[:target],
      run: proc { run_generic_table_tamper(spec) }
    }
  end

  base_profiles
end

def run_profile(profile)
  started = Time.now
  sp004_start = profile[:profile_id] == 'sp004_noop_baseline' ? nil : start_sp004
  score = profile[:run].call
  merged = score.merge(profile_id: profile[:profile_id], name: profile[:name], risk: profile[:risk], target: profile[:target],
                       duration_seconds: Time.now - started)
  merged[:sp004_profile_start] = sp004_start if sp004_start
  merged
rescue SkipProfile => error
  {
    profile_id: profile[:profile_id],
    name: profile[:name],
    risk: profile[:risk],
    target: profile[:target],
    status: 'SKIP',
    verdict: error.reason,
    attack_success: false,
    evidence: {},
    duration_seconds: Time.now - started
  }
rescue Exception => error
  {
    profile_id: profile[:profile_id],
    name: profile[:name],
    risk: profile[:risk],
    target: profile[:target],
    status: 'FAIL',
    verdict: 'verifier_error',
    attack_success: false,
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace&.first(8),
    duration_seconds: Time.now - started
  }
end

def write_summary(report_dir, scores)
  passed = scores.count { |score| score[:status] == 'PASS' }
  failed = scores.count { |score| score[:status] == 'FAIL' }
  skipped = scores.count { |score| score[:status] == 'SKIP' }
  total = scores.length
  summary = {
    scenario_id: SCENARIO_ID,
    scenario_name: SCENARIO_NAME,
    generated_at: Time.now.utc.iso8601,
    attack_description: ATTACK_DESCRIPTION,
    result: failed.zero? ? 'PASS' : 'FAIL',
    profiles_total: total,
    profiles_applicable: total - skipped,
    profiles_passed: passed,
    profiles_failed: failed,
    profiles_skipped: skipped,
    pass_rate: (total - skipped).positive? ? (passed.to_f / (total - skipped)) : 0.0,
    report_dir: report_dir,
    profiles: scores
  }
  write_json(File.join(report_dir, 'summary.json'), summary)

  lines = []
  lines << "# #{SCENARIO_ID} #{SCENARIO_NAME}"
  lines << ""
  lines << "Result: #{summary[:result]}"
  lines << "Profiles: #{passed}/#{total} PASS"
  lines << "Report: #{report_dir}"
  lines << ""
  scores.each do |score|
    lines << "- #{score[:profile_id]}: #{score[:status]} (#{score[:verdict]})"
  end
  File.write(File.join(report_dir, 'summary.md'), lines.join("\n") + "\n")
  summary
end

FileUtils.mkdir_p(REPORT_ROOT)
routes = ensure_routes
write_json(File.join(REPORT_ROOT, 'route_setup.json'), routes)

profiles_to_run = if SELECTED_PROFILE_IDS.empty?
                    profile_definitions
                  else
                    profile_definitions.select { |profile| SELECTED_PROFILE_IDS.include?(profile[:profile_id]) }
                  end

scores = profiles_to_run.map do |profile|
  score = run_profile(profile)
  write_profile_score(REPORT_ROOT, score)
  score
end

summary = write_summary(REPORT_ROOT, scores)
puts "#{SCENARIO_ID} #{SCENARIO_NAME}: #{summary[:result]}"
puts "Profiles: #{summary[:profiles_passed]}/#{summary[:profiles_total]} PASS (#{(summary[:pass_rate] * 100).round(2)}%)"
puts "Report: #{REPORT_ROOT}"
puts ""
scores.each do |score|
  puts "#{score[:profile_id]}: #{score[:status]} - #{score[:verdict]}"
end

exit(summary[:result] == 'PASS' ? 0 : 1)
