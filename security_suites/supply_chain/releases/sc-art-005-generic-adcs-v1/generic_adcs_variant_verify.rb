require 'json'
require 'fileutils'
require 'time'
require 'cosmos'
require 'cosmos/script'

include Cosmos::Script

REPORT_ROOT = ENV.fetch('SC_ART005_REPORT_DIR', "/tmp/sc_art005_generic_adcs/#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}")
EXPECTED_MAX_MCMD = 1.42
TOLERANCE = 0.02

def write_json(path, data)
  FileUtils.mkdir_p(File.dirname(path))
  File.write(path, JSON.pretty_generate(data) + "\n")
end

samples = []
command_result = nil
error = nil

begin
  cmd('GENERIC_ADCS GENERIC_ADCS_SEND_GNC_CC')
  command_result = 'sent'
  8.times do
    sleep 0.5
    samples << tlm('GENERIC_ADCS GENERIC_ADCS_GNC MAX_MCMD').to_f
  end
rescue Exception => exception
  error = { class: exception.class.to_s, message: exception.message }
end

matched = error.nil? && samples.any? { |value| (value - EXPECTED_MAX_MCMD).abs <= TOLERANCE }
score = {
  scenario: 'SC-ART-005',
  release_id: 'sc-art-005-generic-adcs-1.0.1',
  component: 'generic_adcs',
  release_version: '1.0.1.0',
  verification: 'safe_component_replacement_runtime_telemetry',
  command: 'GENERIC_ADCS GENERIC_ADCS_SEND_GNC_CC',
  command_result: command_result,
  telemetry: {
    target: 'GENERIC_ADCS', packet: 'GENERIC_ADCS_GNC', item: 'MAX_MCMD',
    expected: EXPECTED_MAX_MCMD, tolerance: TOLERANCE, samples: samples
  },
  status: matched ? 'PASS' : 'FAIL',
  error: error
}

write_json(File.join(REPORT_ROOT, 'score.json'), score)
write_json(File.join(REPORT_ROOT, 'summary.json'), {
  scenario: score[:scenario], result: score[:status], release_id: score[:release_id],
  component: score[:component], release_version: score[:release_version], report_dir: REPORT_ROOT
})
puts "SC-ART-005 #{score[:status]} component=#{score[:component]} version=#{score[:release_version]}"
exit(matched ? 0 : 1)
