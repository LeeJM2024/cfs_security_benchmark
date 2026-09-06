require 'json'
require 'fileutils'
require 'time'
require 'rexml/document'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

SCENARIO_ID = 'SP005'
SCENARIO_NAME = 'component configuration pollution'
NOS3_ROOT = ENV.fetch('SP005_NOS3_ROOT', '/home/leejm/nos3')
MODE = ENV.fetch('SP005_MODE', 'attack').downcase
REPORT_ROOT = ENV.fetch('SP005_REPORT_DIR', "/tmp/sp005_component_config_pollution_results/#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}")
STATE_PATH = File.join(NOS3_ROOT, '.sp005_component_config_pollution', 'state.json')
PROFILE_MANIFEST_CANDIDATES = [
  ENV['SP005_PROFILE_MANIFEST'],
  '/tmp/sp005_profiles.json',
  File.join(NOS3_ROOT, 'gsw/cosmos/config/targets/MISSION/procedures/sp005_profiles.json'),
  File.join(NOS3_ROOT, 'gsw/cosmos/outputs/tmp/config/targets/MISSION/procedures/sp005_profiles.json'),
  '/home/leejm/Space OS/cfs-security-benchmark/security_suites/space_platform/injections/sp005_component_config_pollution/sp005_profiles.json'
].compact
NUMBER_RE = /[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[Ee][-+]?\d+)?/

class SkipProfile < StandardError
  attr_reader :reason

  def initialize(reason)
    @reason = reason
    super(reason)
  end
end

def write_json(path, object)
  FileUtils.mkdir_p(File.dirname(path))
  File.write(path, JSON.pretty_generate(object) + "\n")
end

def load_profiles
  path = PROFILE_MANIFEST_CANDIDATES.find { |candidate| candidate && File.exist?(candidate) }
  raise "Missing SP005 profile manifest. Checked: #{PROFILE_MANIFEST_CANDIDATES.join(', ')}" unless path

  JSON.parse(File.read(path), symbolize_names: true).map do |profile|
    profile.merge(manifest_path: path)
  end
end

def read_state
  return {} unless File.exist?(STATE_PATH)

  JSON.parse(File.read(STATE_PATH), symbolize_names: true)
rescue Exception => error
  { state_error: error.message }
end

def active_profiles_from_state(state)
  active_profiles = Array(state[:active_profiles]).map(&:to_s)
  legacy_active = state[:active_profile].to_s
  active_profiles << legacy_active unless legacy_active.empty? || active_profiles.include?(legacy_active)
  active_profiles
end

def requested_profile_id
  requested = ENV['SP005_PROFILE']
  return nil if requested.nil? || requested.strip.empty?

  requested.strip
end

def all_profiles_requested?
  requested = requested_profile_id
  return true if ENV['SP005_RUN_ALL'].to_s == '1'
  return true if requested.nil?

  ['all', '*'].include?(requested.downcase)
end

def profile_by_id(profiles, profile_id)
  profiles.find { |candidate| candidate[:id].to_s == profile_id.to_s }
end

def select_profile(profiles, _state)
  requested = requested_profile_id
  raise SkipProfile, 'SP005_PROFILE must be a profile id for single-profile mode, or all for batch mode.' if requested.nil?
  raise SkipProfile, 'SP005_PROFILE=all selects batch mode, not a single profile.' if ['all', '*'].include?(requested.downcase)

  profile = profile_by_id(profiles, requested)
  raise SkipProfile, "Unknown SP005 profile #{requested}" unless profile

  profile
end

def batch_profiles(profiles, state)
  active_profiles = active_profiles_from_state(state)
  profile_ids = MODE == 'attack' && !active_profiles.empty? ? active_profiles : profiles.map { |profile| profile[:id].to_s }

  selected = []
  missing = []
  profile_ids.each do |profile_id|
    profile = profile_by_id(profiles, profile_id)
    profile ? selected << profile : missing << profile_id
  end

  raise SkipProfile, "Unknown active SP005 profile(s): #{missing.join(', ')}" unless missing.empty?
  raise SkipProfile, 'No SP005 profiles available for batch verification.' if selected.empty?

  selected
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

def cmd_optional(target, command)
  cmd("#{target} #{command}")
  { ok: true, command: "#{target} #{command}" }
rescue Exception => error
  { ok: false, command: "#{target} #{command}", error_class: error.class.to_s, error: error.message }
end

def tlm_optional(target, packet, item)
  value = tlm("#{target} #{packet} #{item}")
  { ok: true, target: target, packet: packet, item: item, value: numeric(value), raw: value }
rescue Exception => error
  { ok: false, target: target, packet: packet, item: item, error_class: error.class.to_s, error: error.message }
end

def numeric(value)
  return value.to_f if value.is_a?(Numeric)

  value.to_s.strip.to_f
end

def wait_for_tlm(target, packet, item, expected, tolerance, timeout_seconds = 8.0, interval = 0.5, range: nil)
  deadline = Time.now + timeout_seconds
  samples = []
  last = nil

  until Time.now >= deadline
    last = tlm_optional(target, packet, item)
    samples << last if samples.length < 10
    if last[:ok]
      if range && within_range?(last[:value], range[:min], range[:max])
        return { matched: true, reason: 'telemetry_range_matched', expected_range: range, expected: expected, tolerance: tolerance, last: last, samples: samples }
      elsif range.nil? && within_tolerance?(last[:value], expected, tolerance)
        return { matched: true, reason: 'telemetry_value_matched', expected: expected, tolerance: tolerance, last: last, samples: samples }
      end
    end
    sleep(interval)
  end

  result = { matched: false, reason: 'telemetry_value_not_observed', expected: expected, tolerance: tolerance, last: last, samples: samples }
  result[:expected_range] = range if range
  result
end

def within_tolerance?(actual, expected, tolerance)
  (actual.to_f - expected.to_f).abs <= tolerance.to_f
end

def within_range?(actual, min_value, max_value)
  value = actual.to_f
  value >= min_value.to_f && value <= max_value.to_f
end

def source_path(profile)
  File.join(NOS3_ROOT, profile[:path])
end

def generated_paths(profile)
  Array(profile[:generated_paths]).map { |relative| File.join(NOS3_ROOT, relative) }
end

def latest_profile_changes(state, profile)
  Array(state[:history]).reverse_each do |entry|
    next unless entry[:profile].to_s == profile[:id].to_s
    return Array(entry[:changes]) if entry[:changes].is_a?(Array)
  end

  []
end

def change_for_token(changes, token_index, anchor = nil)
  changes.find do |change|
    change[:token_index].to_i == token_index.to_i && (anchor.nil? || change[:anchor].nil? || change[:anchor].to_s == anchor.to_s)
  end
end

def original_config_values(profile, state)
  changes = latest_profile_changes(state, profile)

  case profile[:mutator]
  when 'anchored_numeric_token'
    change = change_for_token(changes, profile[:token_index], profile[:anchor])
    [change ? change[:old].to_s : profile[:expected_original].to_s]
  when 'anchored_numeric_tokens'
    Array(profile[:replacements]).map do |replacement|
      change = change_for_token(changes, replacement[:token_index], profile[:anchor])
      change ? change[:old].to_s : replacement[:expected_original].to_s
    end
  when 'xml_text'
    xml_path = Array(profile[:xml_path]).join('/')
    change = changes.find { |item| item[:xml_path].to_s == xml_path } || changes.first
    change ? change[:old].to_s : profile[:expected_original].to_s
  else
    []
  end
end

def expected_value(profile, state)
  MODE == 'restore' ? original_config_values(profile, state).first : profile[:malicious_value]
end

def expected_replacements(profile, state)
  return original_config_values(profile, state) if MODE == 'restore'

  Array(profile[:replacements]).map { |replacement| replacement[:malicious_value].to_s }
end

def telemetry_item_specs(telemetry)
  telemetry[:item] ? [telemetry[:item]] : Array(telemetry[:items])
end

def expected_telemetry_value(profile, state)
  telemetry = profile[:telemetry]
  return nil unless telemetry
  return telemetry_expectations(profile, state) if telemetry[:items].is_a?(Array)

  telemetry_item_expected(profile, telemetry, telemetry[:item] || telemetry, state, 0)
end

def telemetry_item_expected(profile, telemetry, item_spec, state, index = 0)
  spec = item_spec.is_a?(Hash) ? item_spec : telemetry
  return spec[:expected_attack] unless MODE == 'restore'

  originals = original_config_values(profile, state)
  return originals[index].to_f if originals[index] && numeric_expected?(spec)
  return originals[index] if originals[index]
  return originals.first.to_f if originals.length == 1 && numeric_expected?(spec)
  return originals.first if originals.length == 1

  spec[:expected_original]
end

def numeric_expected?(spec)
  spec.key?(:expected_attack) || spec.key?(:expected_original) || spec.key?(:expected_attack_min) || spec.key?(:expected_restore_min)
end

def telemetry_item_tolerance(telemetry, item_spec)
  spec = item_spec.is_a?(Hash) ? item_spec : telemetry
  spec.fetch(:tolerance, telemetry.fetch(:tolerance, 0.001)).to_f
end

def telemetry_item_range(profile, telemetry, item_spec, state, index = 0)
  spec = item_spec.is_a?(Hash) ? item_spec : telemetry
  min_key = MODE == 'restore' ? :expected_restore_min : :expected_attack_min
  max_key = MODE == 'restore' ? :expected_restore_max : :expected_attack_max
  return nil unless spec.key?(min_key) && spec.key?(max_key)

  min_value = spec[min_key].to_f
  max_value = spec[max_key].to_f

  if MODE == 'restore'
    baseline_expected = spec[:expected_original] || telemetry[:expected_original]
    restored_expected = telemetry_item_expected(profile, telemetry, item_spec, state, index)
    if baseline_expected && restored_expected
      offset = restored_expected.to_f - baseline_expected.to_f
      min_value += offset
      max_value += offset
    end
  end

  { min: min_value, max: max_value }
end

def telemetry_range(profile, state)
  telemetry = profile[:telemetry]
  return nil unless telemetry

  telemetry_item_range(profile, telemetry, telemetry, state, 0)
end

def telemetry_expectations(profile, state)
  telemetry = profile[:telemetry]
  return nil unless telemetry

  telemetry_item_specs(telemetry).each_with_index.map do |item_spec, index|
    item_name = item_spec.is_a?(Hash) ? item_spec[:item] : item_spec
    { item: item_name, expected: telemetry_item_expected(profile, telemetry, item_spec, state, index), tolerance: telemetry_item_tolerance(telemetry, item_spec), range: telemetry_item_range(profile, telemetry, item_spec, state, index) }
  end
end

def anchored_numeric_values(path, anchor, token_indexes, line_match_index = nil)
  return { ok: false, path: path, error: 'file_missing' } unless File.exist?(path)

  lines = File.readlines(path, chomp: true)
  matches = lines.each_with_index.select { |line, _index| line.include?(anchor) }
  selected_match = line_match_index.nil? ? nil : line_match_index.to_i
  if selected_match.nil?
    return { ok: false, path: path, error: "anchor_match_count_#{matches.length}", anchor: anchor } if matches.length != 1
    selected_match = 0
  end
  if selected_match < 0 || selected_match >= matches.length
    return { ok: false, path: path, error: "line_match_index_#{selected_match}_out_of_range_#{matches.length}", anchor: anchor }
  end

  line, index = matches[selected_match]
  numbers = line.split('!', 2).first.scan(NUMBER_RE)
  values = token_indexes.map do |token_index|
    numbers[token_index]
  end
  { ok: true, path: path, line: index + 1, line_match_index: selected_match, anchor: anchor, values: values, line_text: line }
end


def xml_regex_fallback_value(path, xml_path)
  return nil unless File.exist?(path)

  text = File.read(path)
  if xml_path.length >= 2
    parent = xml_path[-2]
    tag = xml_path[-1]
    parent_match = text.match(%r{<#{Regexp.escape(parent)}>.*?<#{Regexp.escape(tag)}>\s*([^<]+?)\s*</#{Regexp.escape(tag)}>.*?</#{Regexp.escape(parent)}>}m)
    return parent_match[1].strip if parent_match
  end

  tag = xml_path.last
  match = text.match(%r{<#{Regexp.escape(tag)}>\s*([^<]+?)\s*</#{Regexp.escape(tag)}>})
  match && match[1].strip
end

def xml_text_value(path, xml_path)
  return { ok: false, path: path, error: 'file_missing' } unless File.exist?(path)

  document = REXML::Document.new(File.read(path))
  node = document.root
  xml_path.each do |part|
    node = node.elements[part]
    break if node.nil?
  end
  return { ok: true, path: path, xml_path: xml_path.join('/'), value: node.text.to_s.strip } if node

  # Aggregated NOS3 simulator XML can contain several simulator nodes and can be malformed.
  fallback_value = xml_regex_fallback_value(path, xml_path)
  return { ok: true, path: path, xml_path: xml_path.join('/'), value: fallback_value, parser_fallback: true } if fallback_value

  { ok: false, path: path, error: "xml_path_missing_#{xml_path.join('/')}" }
rescue Exception => error
  fallback_value = xml_regex_fallback_value(path, xml_path)
  return { ok: true, path: path, xml_path: xml_path.join('/'), value: fallback_value, parser_fallback: true } if fallback_value

  { ok: false, path: path, error_class: error.class.to_s, error: error.message }
end

def config_observation(profile, path)
  case profile[:mutator]
  when 'anchored_numeric_token'
    anchored_numeric_values(path, profile[:anchor], [profile[:token_index].to_i], profile[:line_match_index])
  when 'anchored_numeric_tokens'
    anchored_numeric_values(path, profile[:anchor], profile[:replacements].map { |replacement| replacement[:token_index].to_i }, profile[:line_match_index])
  when 'xml_text'
    xml_text_value(path, profile[:xml_path])
  else
    { ok: false, path: path, error: "unsupported_mutator_#{profile[:mutator]}" }
  end
end

def config_matches?(profile, observation, state)
  return false unless observation[:ok]

  case profile[:mutator]
  when 'anchored_numeric_token'
    observation[:values] == [expected_value(profile, state).to_s]
  when 'anchored_numeric_tokens'
    observation[:values] == expected_replacements(profile, state)
  when 'xml_text'
    observation[:value] == expected_value(profile, state).to_s
  else
    false
  end
end

def wait_for_observed_tlm(target, packet, item, timeout_seconds = 8.0, interval = 0.5)
  deadline = Time.now + timeout_seconds
  samples = []
  last = nil

  until Time.now >= deadline
    last = tlm_optional(target, packet, item)
    samples << last if samples.length < 10
    return { matched: true, reason: 'telemetry_observed', last: last, samples: samples } if last[:ok]

    sleep(interval)
  end

  { matched: false, reason: 'telemetry_not_observed', last: last, samples: samples }
end

def telemetry_item_name(item_spec)
  item_spec.is_a?(Hash) ? item_spec[:item] : item_spec
end

def verify_telemetry(profile, state)
  telemetry = profile[:telemetry]
  return { ok: false, matched: false, reason: 'telemetry_not_configured' } unless telemetry

  target = telemetry[:target]
  command = telemetry[:command]
  packet = telemetry[:packet]
  match_mode = telemetry.fetch(:match, 'exact').to_s

  unless command_target_exists?(target)
    return { ok: false, matched: false, reason: 'cosmos_command_target_missing', target: target }
  end
  unless telemetry_packet_exists?(target, packet)
    return { ok: false, matched: false, reason: 'cosmos_telemetry_packet_missing', target: target, packet: packet }
  end

  setup_results = Array(telemetry[:setup_commands]).map do |setup_command|
    result = cmd_optional(target, setup_command)
    sleep(0.5)
    result
  end

  command_result = cmd_optional(target, command)
  sleep(0.5)

  item_specs = telemetry_item_specs(telemetry)
  waits = item_specs.each_with_index.map do |item_spec, index|
    item = telemetry_item_name(item_spec)
    wait = if match_mode == 'observe'
             wait_for_observed_tlm(target, packet, item)
           else
             expected = telemetry_item_expected(profile, telemetry, item_spec, state, index).to_f
             tolerance = telemetry_item_tolerance(telemetry, item_spec)
             range = telemetry_item_range(profile, telemetry, item_spec, state, index)
             wait_for_tlm(target, packet, item, expected, tolerance, range: range)
           end
    wait.merge(item: item)
  end

  matched = waits.all? { |wait| wait[:matched] }
  result = { ok: matched, matched: matched, setup_commands: setup_results, command: command_result, waits: waits, match_mode: match_mode }
  result[:wait] = waits.first if waits.length == 1
  result[:reason] = waits.find { |wait| !wait[:matched] }[:reason] unless matched
  result
end

def current_generated_observations(profile)
  paths = generated_paths(profile)
  observations = paths.map { |path| config_observation(profile, path) }
  existing = observations.select { |observation| observation[:ok] || File.exist?(observation[:path]) }
  existing.empty? ? observations : existing
end

def classify_failure(source_match, generated_match, telemetry_result, source_observation, generated_observations)
  return 'config_source_not_polluted_or_not_restored' unless source_match
  return 'build_artifact_not_updated_run_make_config_fsw' unless generated_match
  return telemetry_result[:reason] if telemetry_result[:reason]
  return 'runtime_effect_not_observed' unless telemetry_result[:matched]

  'inconclusive'
end

def run_profile(profile, state)
  source_observation = config_observation(profile, source_path(profile))
  generated_observations = current_generated_observations(profile)
  telemetry_result = verify_telemetry(profile, state)

  source_match = config_matches?(profile, source_observation, state)
  generated_matches = generated_observations.any? && generated_observations.all? { |observation| config_matches?(profile, observation, state) }
  telemetry_match = telemetry_result[:matched]
  success = source_match && generated_matches && telemetry_match

  active_profiles = active_profiles_from_state(state)
  evidence = {
    mode: MODE,
    active_profile_from_state: state[:active_profile],
    active_profiles_from_state: active_profiles,
    selected_profile_active_in_state: active_profiles.include?(profile[:id].to_s),
    source_config_expected_value: expected_value(profile, state),
    source_config_observation: source_observation,
    source_config_matches_expected: source_match,
    generated_config_observations: generated_observations,
    generated_configs_match_expected: generated_matches,
    telemetry_expected_value: expected_telemetry_value(profile, state),
    telemetry_expected_range: telemetry_range(profile, state),
    telemetry_result: telemetry_result,
    telemetry_matches_expected: telemetry_match
  }

  verdict = success ? 'attack_success_component_runtime_config_polluted' :
            classify_failure(source_match, generated_matches, telemetry_result, source_observation, generated_observations)
  verdict = 'restore_success_component_runtime_config_normal' if success && MODE == 'restore'

  {
    scenario: SCENARIO_ID,
    scenario_name: SCENARIO_NAME,
    profile_id: profile[:id],
    profile_title: profile[:title],
    component: profile[:component],
    status: success ? 'PASS' : 'FAIL',
    verdict: verdict,
    attack_success: MODE == 'attack' && success,
    restore_success: MODE == 'restore' && success,
    security_consequence: profile[:security_consequence],
    evidence: evidence,
    state: state,
    manifest_path: profile[:manifest_path]
  }
end

def write_report(score, report_root = REPORT_ROOT)
  FileUtils.mkdir_p(report_root)
  write_json(File.join(report_root, 'score.json'), score)
  summary = {
    scenario: SCENARIO_ID,
    result: score[:status],
    mode: MODE,
    profile_id: score[:profile_id],
    verdict: score[:verdict],
    report_dir: report_root
  }
  write_json(File.join(report_root, 'summary.json'), summary)

  lines = []
  lines << "# #{SCENARIO_ID} #{SCENARIO_NAME}"
  lines << ''
  lines << "Profile: #{score[:profile_id]}"
  lines << "Component: #{score[:component]}"
  lines << "Mode: #{MODE}"
  lines << "Status: #{score[:status]}"
  lines << "Verdict: #{score[:verdict]}"
  lines << ''
  lines << 'Security consequence:'
  lines << score[:security_consequence].to_s
  lines << ''
  lines << 'Evidence summary:'
  score[:evidence].each do |key, value|
    lines << "- #{key}: #{value.inspect[0, 500]}"
  end
  File.write(File.join(report_root, 'report.md'), lines.join("\n") + "\n")

  summary
end

def safe_report_name(value)
  value.to_s.gsub(/[^A-Za-z0-9_.-]/, '_')
end

def skip_score(error, profile_id = ENV['SP005_PROFILE'])
  {
    scenario: SCENARIO_ID,
    scenario_name: SCENARIO_NAME,
    profile_id: profile_id,
    status: 'SKIP',
    verdict: 'not_applicable_or_not_prepared',
    reason: error.reason,
    attack_success: false,
    restore_success: false,
    evidence: { mode: MODE, state: read_state }
  }
end

def verifier_error_score(error, profile_id = ENV['SP005_PROFILE'])
  {
    scenario: SCENARIO_ID,
    scenario_name: SCENARIO_NAME,
    profile_id: profile_id,
    status: 'FAIL',
    verdict: 'verifier_error',
    error_class: error.class.to_s,
    error: error.message,
    backtrace: error.backtrace&.first(20),
    attack_success: false,
    restore_success: false,
    evidence: { mode: MODE, state: read_state }
  }
end

def write_batch_report(scores, report_root = REPORT_ROOT)
  FileUtils.mkdir_p(report_root)
  result = scores.all? { |score| score[:status] == 'PASS' } ? 'PASS' : 'FAIL'
  summary = {
    scenario: SCENARIO_ID,
    result: result,
    mode: MODE,
    profile_count: scores.length,
    pass_count: scores.count { |score| score[:status] == 'PASS' },
    fail_count: scores.count { |score| score[:status] == 'FAIL' },
    skip_count: scores.count { |score| score[:status] == 'SKIP' },
    profiles: scores.map do |score|
      {
        profile_id: score[:profile_id],
        status: score[:status],
        verdict: score[:verdict],
        report_dir: File.join(report_root, safe_report_name(score[:profile_id]))
      }
    end,
    report_dir: report_root
  }

  write_json(File.join(report_root, 'summary.json'), summary)
  write_json(File.join(report_root, 'score.json'), {
    scenario: SCENARIO_ID,
    scenario_name: SCENARIO_NAME,
    status: result,
    mode: MODE,
    results: scores,
    summary: summary
  })

  lines = []
  lines << "# #{SCENARIO_ID} #{SCENARIO_NAME}"
  lines << ''
  lines << "Mode: #{MODE}"
  lines << "Status: #{result}"
  lines << "Profiles: #{scores.length}"
  lines << ''
  lines << 'Profile results:'
  summary[:profiles].each do |profile|
    lines << "- #{profile[:profile_id]}: #{profile[:status]} #{profile[:verdict]}"
  end
  File.write(File.join(report_root, 'report.md'), lines.join("\n") + "\n")

  summary
end

begin
  profiles = load_profiles
  state = read_state

  if all_profiles_requested?
    scores = []
    batch_profiles(profiles, state).each do |profile|
      score = begin
        run_profile(profile, state)
      rescue SkipProfile => error
        skip_score(error, profile[:id])
      rescue Exception => error
        verifier_error_score(error, profile[:id])
      end

      profile_report_root = File.join(REPORT_ROOT, safe_report_name(profile[:id]))
      write_report(score, profile_report_root)
      puts "#{SCENARIO_ID} #{score[:status]} profile=#{score[:profile_id]} mode=#{MODE} verdict=#{score[:verdict]}"
      scores << score
    end

    summary = write_batch_report(scores)
    puts "#{SCENARIO_ID} #{summary[:result]} batch mode=#{MODE} profiles=#{summary[:profile_count]} pass=#{summary[:pass_count]} fail=#{summary[:fail_count]} skip=#{summary[:skip_count]}"
    puts "Report: #{REPORT_ROOT}"
    exit(summary[:result] == 'PASS' ? 0 : 1)
  end

  profile = select_profile(profiles, state)
  score = run_profile(profile, state)
rescue SkipProfile => error
  score = skip_score(error)
rescue StandardError => error
  score = verifier_error_score(error)
end

summary = write_report(score)
puts "#{SCENARIO_ID} #{score[:status]} profile=#{score[:profile_id]} mode=#{MODE} verdict=#{score[:verdict]}"
puts "Report: #{summary[:report_dir]}"
exit(score[:status] == 'PASS' ? 0 : 1)
