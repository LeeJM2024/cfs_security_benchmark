require 'json'
require 'fileutils'
require 'open3'
require 'socket'
require 'time'
require 'timeout'
require 'cosmos'
require 'cosmos/script'
include Cosmos::Script

SCENARIO_ID='SP007'
SCENARIO_NAME='Resource exhaustion'
REPORT_ROOT=ENV.fetch('SP007_REPORT_DIR',"/tmp/sp007_resource_exhaustion_results/#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}")
CI_HOST=ENV.fetch('SP007_CI_HOST','sc01-nos-fsw')
CI_PORT=ENV.fetch('SP007_CI_PORT','5012').to_i
FSW_CONTAINER=ENV.fetch('SP007_FSW_CONTAINER','sc01-nos-fsw')
SELECTED=ENV.fetch('SP007_ONLY','').split(',').map(&:strip).reject(&:empty?)

SP007_CMD_MID=0x19F8
SP007_REQ_HK_MID=0x19F9
SP007_HK_MID=0x09F8
SP007_FLOOD_MID=0x09F9
SP007_START_CC=2
SP007_STOP_CC=3
SP007_CLEANUP_CC=4
TO_LAB_CMD_MID=0x18E8
TO_LAB_ENABLE_OUTPUT_CC=2
EVS_MID=0x0808
SB_CMD_MID=0x1803
SB_HK_MID=0x0803
SB_STAT_MID=0x080A
FM_CMD_MID=0x188C
FM_FILE_INFO_MID=0x088B
FM_GET_FILE_INFO_CC=10
SB_SEND_STATS_CC=2

PROFILES=[
 {id:1,name:'CPU_BUSY_STARVATION',title:'CPU busy-loop child tasks degrade command/telemetry responsiveness',expected:'attack_success_if_cpu_pressure_causes_system_level_latency',args:{duration_ms:9000,rate_or_yield:8_000_000,limit:0,arg1:8}},
 {id:2,name:'SB_TELEMETRY_FLOOD',title:'Unauthorized high-rate Software Bus telemetry injection',expected:'attack_success_if_flood_causes_to_lab_drop_or_victim_hk_degradation',args:{duration_ms:8000,rate_or_yield:5,limit:200_000}},
 {id:3,name:'EVS_EVENT_STORM',title:'High-volume EVS event storm',expected:'attack_success_if_evs_packets_or_fsw_logs_show_event_flood',args:{duration_ms:3000,rate_or_yield:0,limit:3_000}},
 {id:4,name:'CF_STORAGE_FILL',title:'Onboard /cf storage fill file',expected:'attack_success_if_untrusted_app_can_consume_cf_storage_until_cleanup',args:{duration_ms:30000,rate_or_yield:0,limit:65_536}},
 {id:5,name:'OSAL_QUEUE_EXHAUST',title:'Held SB pipes and OSAL queues reduce IPC resource margin',expected:'attack_success_if_cfe_sb_statistics_show_pipe_resource_consumption',args:{duration_ms:1000,rate_or_yield:0,limit:40,arg1:24}}
].freeze

class SkipProfile<StandardError
 attr_reader :reason
 def initialize(reason); @reason=reason; super(reason); end
end

def json_safe(v)
 case v
 when Hash then v.each_with_object({}){|(k,x),o| o[k]=json_safe(x)}
 when Array then v.map{|x| json_safe(x)}
 when Numeric,String,TrueClass,FalseClass,NilClass then v
 else v.to_s
 end
end

def write_json(path,obj)
 FileUtils.mkdir_p(File.dirname(path)); File.write(path,JSON.pretty_generate(json_safe(obj))+"\n")
end

def write_profile_score(dir,score)
 p=File.join(dir,'profiles',score[:profile_name].to_s); FileUtils.mkdir_p(p); write_json(File.join(p,'score.json'),score)
end

def shell_capture(cmd,timeout_seconds:8)
 out=nil; err=nil; st=nil
 Timeout.timeout(timeout_seconds){out,err,st=Open3.capture3(cmd)}
 {ok:st.success?,exit_status:st.exitstatus,stdout:(out.to_s[-12000,12000]||out.to_s),stderr:(err.to_s[-4000,4000]||err.to_s),command:cmd}
rescue Exception=>e
 {ok:false,error_class:e.class.to_s,error:e.message,command:cmd}
end

def cfe_checksum(pkt)
 v=0xFF; pkt.each_byte{|b| v^=b}; v&0xFF
end

def command_packet(mid,fc,payload=''.b)
 pkt=[mid&0xFFFF,0xC000,(8+payload.bytesize-7)&0xFFFF].pack('n n n')
 pkt << [fc&0xFF,0].pack('C C') << payload
 pkt.setbyte(7,cfe_checksum(pkt)); pkt
end

def send_udp(pkt)
 UDPSocket.open{|s| s.send(pkt,0,CI_HOST,CI_PORT)}
 {ok:true,host:CI_HOST,port:CI_PORT,bytes:pkt.bytesize,checksum_result:cfe_checksum(pkt)}
rescue Exception=>e
 {ok:false,host:CI_HOST,port:CI_PORT,error_class:e.class.to_s,error:e.message}
end

def raw_to_lab_add(mid,limit=64)
 payload=[mid&0xFFFFFFFF].pack('V')+[0,0,limit&0xFF,0].pack('C C C C')
 send_udp(command_packet(TO_LAB_CMD_MID,6,payload))
end

def raw_to_lab_enable
 ip='active-gs'.bytes.pack('C*')
 payload=ip+("\0".b*(16-ip.bytesize))
 send_udp(command_packet(TO_LAB_CMD_MID,TO_LAB_ENABLE_OUTPUT_CC,payload))
end

def ensure_routes
 routes={to_lab_enable:raw_to_lab_enable}
 sleep 0.2
 {evs:EVS_MID,sp007_hk:SP007_HK_MID,sp007_flood:SP007_FLOOD_MID,sb_hk:SB_HK_MID,sb_stats:SB_STAT_MID,fm_file_info:FM_FILE_INFO_MID}.each do |n,m|
  routes[n]=raw_to_lab_add(m,n==:sp007_flood ? 128 : 64); sleep 0.15
 end
 routes
end

def packet_exists?(target,packet)
 Cosmos::System.telemetry.packet(target,packet); true
rescue Exception
 false
end

def num(v); v.is_a?(Numeric) ? v.to_f : v.to_s.strip.to_f; end

def tlm_i(target,packet,item); num(tlm("#{target} #{packet} #{item}")).to_i; end

def tlm_i_optional(target,packet,item)
 {ok:true,value:tlm_i(target,packet,item)}
rescue Exception=>e
 {ok:false,error_class:e.class.to_s,error:e.message}
end

def clean(v); v.to_s.delete("\x00").strip; end
def request_sp007_hk; send_udp(command_packet(SP007_REQ_HK_MID,0,''.b)); end
def request_sb_stats; send_udp(command_packet(SB_CMD_MID,SB_SEND_STATS_CC,''.b)); end

def read_sp007_hk(refresh:true)
 return {available:false,reason:'SP007 telemetry dictionary is not loaded'} unless packet_exists?('CFS','SP007_HK_TLM')
 request_sp007_hk && sleep(0.25) if refresh
 ps=tlm_i_optional('CFS','SP007_HK_TLM','PROFILESTARTED')
 {available:true,sequence:tlm_i('CFS','SP007_HK_TLM','CCSDS_SEQUENCE'),cmd_count:tlm_i('CFS','SP007_HK_TLM','COMMANDCOUNT'),err_count:tlm_i('CFS','SP007_HK_TLM','COMMANDERRORCOUNT'),active_profile_id:tlm_i('CFS','SP007_HK_TLM','ACTIVEPROFILEID'),last_profile_id:tlm_i('CFS','SP007_HK_TLM','LASTPROFILEID'),last_resource_id:tlm_i('CFS','SP007_HK_TLM','LASTRESOURCEID'),last_status:tlm_i('CFS','SP007_HK_TLM','LASTSTATUS'),profiles_started:(ps[:ok] ? ps[:value] : 0),profiles_completed:tlm_i('CFS','SP007_HK_TLM','PROFILESCOMPLETED'),cleanup_count:tlm_i('CFS','SP007_HK_TLM','CLEANUPCOUNT'),worker_task_count:tlm_i('CFS','SP007_HK_TLM','WORKERTASKCOUNT'),cpu_worker_count:tlm_i('CFS','SP007_HK_TLM','CPUWORKERCOUNT'),sb_transmit_count:tlm_i('CFS','SP007_HK_TLM','SBTRANSMITCOUNT'),sb_transmit_error_count:tlm_i('CFS','SP007_HK_TLM','SBTRANSMITERRORCOUNT'),evs_send_count:tlm_i('CFS','SP007_HK_TLM','EVSSENDCOUNT'),evs_send_error_count:tlm_i('CFS','SP007_HK_TLM','EVSSENDERRORCOUNT'),file_bytes_written:tlm_i('CFS','SP007_HK_TLM','FILEBYTESWRITTEN'),file_write_error_count:tlm_i('CFS','SP007_HK_TLM','FILEWRITEERRORCOUNT'),held_pipe_count:tlm_i('CFS','SP007_HK_TLM','HELDPIPECOUNT'),held_queue_count:tlm_i('CFS','SP007_HK_TLM','HELDQUEUECOUNT'),last_api_status:tlm_i('CFS','SP007_HK_TLM','LASTAPISTATUS'),active:tlm_i('CFS','SP007_HK_TLM','ACTIVE'),stop_requested:tlm_i('CFS','SP007_HK_TLM','STOPREQUESTED'),file_present:tlm_i('CFS','SP007_HK_TLM','FILEPRESENT')}
rescue Exception=>e
 {available:false,error_class:e.class.to_s,error:e.message}
end

def read_flood_tlm
 return {available:false,reason:'SP007 flood telemetry dictionary is not loaded'} unless packet_exists?('CFS','SP007_FLOOD_TLM')
 {available:true,ccsds_sequence:tlm_i('CFS','SP007_FLOOD_TLM','CCSDS_SEQUENCE'),sequence:tlm_i('CFS','SP007_FLOOD_TLM','SEQUENCE'),profile_id:tlm_i('CFS','SP007_FLOOD_TLM','PROFILEID')}
rescue Exception=>e
 {available:false,error_class:e.class.to_s,error:e.message}
end

def read_sb_hk
 return {available:false,reason:'CFE_SB_HKMSG telemetry dictionary is not loaded'} unless packet_exists?('CFS','CFE_SB_HKMSG')
 {available:true,sequence:tlm_i('CFS','CFE_SB_HKMSG','CCSDS_SEQUENCE'),no_subscribers_count:tlm_i('CFS','CFE_SB_HKMSG','NOSUBSCRIBERSCNT'),msg_send_error_count:tlm_i('CFS','CFE_SB_HKMSG','MSGSENDERRCNT'),msg_receive_error_count:tlm_i('CFS','CFE_SB_HKMSG','MSGRECEIVEERRCNT'),internal_error_count:tlm_i('CFS','CFE_SB_HKMSG','INTERNALERRCNT'),create_pipe_error_count:tlm_i('CFS','CFE_SB_HKMSG','CREATEPIPEERRCNT'),pipe_overflow_error_count:tlm_i('CFS','CFE_SB_HKMSG','PIPEOVERFLOWERRCNT'),msg_limit_error_count:tlm_i('CFS','CFE_SB_HKMSG','MSGLIMERRCNT'),mem_in_use:tlm_i('CFS','CFE_SB_HKMSG','MEMINUSE')}
rescue Exception=>e
 {available:false,error_class:e.class.to_s,error:e.message}
end

def read_sb_stats(refresh:true)
 return {available:false,reason:'CFE_SB_STATMSG telemetry dictionary is not loaded'} unless packet_exists?('CFS','CFE_SB_STATMSG')
 request_sb_stats && sleep(0.35) if refresh
 {available:true,sequence:tlm_i('CFS','CFE_SB_STATMSG','CCSDS_SEQUENCE'),msgids_in_use:tlm_i('CFS','CFE_SB_STATMSG','MSGIDSINUSE'),pipes_in_use:tlm_i('CFS','CFE_SB_STATMSG','PIPESINUSE'),peak_pipes_in_use:tlm_i('CFS','CFE_SB_STATMSG','PEAKPIPESINUSE'),max_pipes_allowed:tlm_i('CFS','CFE_SB_STATMSG','MAXPIPESALLOWED'),mem_in_use:tlm_i('CFS','CFE_SB_STATMSG','MEMINUSE'),peak_mem_in_use:tlm_i('CFS','CFE_SB_STATMSG','PEAKMEMINUSE'),max_mem_allowed:tlm_i('CFS','CFE_SB_STATMSG','MAXMEMALLOWED'),subscriptions_in_use:tlm_i('CFS','CFE_SB_STATMSG','SUBSCRIPTIONSINUSE'),sb_buffers_in_use:tlm_i('CFS','CFE_SB_STATMSG','SBBUFFERSINUSE'),peak_sb_buffers_in_use:tlm_i('CFS','CFE_SB_STATMSG','PEAKSBBUFFERSINUSE')}
rescue Exception=>e
 {available:false,error_class:e.class.to_s,error:e.message}
end

def read_event_packet
 {sequence:tlm_i('CFS','CFE_EVS_PACKET','CCSDS_SEQUENCE'),app_name:clean(tlm('CFS CFE_EVS_PACKET PACKETID_APPNAME')),event_id:tlm_i('CFS','CFE_EVS_PACKET','PACKETID_EVENTID'),event_type:tlm_i('CFS','CFE_EVS_PACKET','PACKETID_EVENTTYPE'),message:clean(tlm('CFS CFE_EVS_PACKET MESSAGE')),observed_at:Time.now.utc.iso8601}
end

def collect_events(seconds=4.0,interval=0.06)
 deadline=Time.now+seconds; events=[]; errors=[]; last=nil
 until Time.now>=deadline
  begin
   ev=read_event_packet
   if !ev[:sequence].nil? && ev[:sequence]!=last then events << ev; last=ev[:sequence]; end
  rescue Exception=>e
   errors << {error_class:e.class.to_s,error:e.message} if errors.length<5
  end
  sleep interval
 end
 {events:events,errors:errors}
end

def docker_logs_since(seconds,pattern='SP007|CFE_SB|CFE_EVS|OS_Queue|CreatePipe|overflow|error|Error|Failed')
 shell_capture("docker logs --since #{seconds}s #{FSW_CONTAINER} 2>&1 | grep -E '#{pattern}' | tail -300",timeout_seconds:8)
end

def cf_file_state
 cmd="docker exec #{FSW_CONTAINER} sh -lc 'echo SP007_FILE; if [ -f /cf/sp007_fill.dat ]; then stat -c %s /cf/sp007_fill.dat; else echo MISSING; fi; echo SP007_DF; df -k /cf 2>/dev/null || df -k /cf'"
 r=shell_capture(cmd,timeout_seconds:8); s=r[:stdout].to_s[/SP007_FILE\s+([^\s]+)/m,1]
 r.merge(file_size:(s && s!='MISSING' ? s.to_i : nil),file_missing:(s=='MISSING'))
end

def fm_get_file_info(path='/cf/sp007_fill.dat')
 name=path.to_s.bytes.first(63).pack('C*')
 payload=name+("\0".b*(64-name.bytesize))+[0].pack('V')
 send_udp(command_packet(FM_CMD_MID,FM_GET_FILE_INFO_CC,payload))
end

def read_fm_file_info(refresh:true,path:'/cf/sp007_fill.dat')
 return {available:false,reason:'FM_FILEINFOPKT telemetry dictionary is not loaded'} unless packet_exists?('CFS','FM_FILEINFOPKT')
 fm_get_file_info(path) && sleep(0.7) if refresh
 fname=clean(tlm('CFS FM_FILEINFOPKT FILENAME'))
 {available:true,sequence:tlm_i('CFS','FM_FILEINFOPKT','CCSDS_SEQUENCE'),file_status:tlm_i('CFS','FM_FILEINFOPKT','FILESTATUS'),crc_computed:tlm_i('CFS','FM_FILEINFOPKT','CRCCOMPUTED'),file_size:tlm_i('CFS','FM_FILEINFOPKT','FILESIZE'),mode:tlm_i('CFS','FM_FILEINFOPKT','MODE'),filename:fname,filename_matches:fname.include?(path)}
rescue Exception=>e
 {available:false,error_class:e.class.to_s,error:e.message}
end

def wait_fm_file_info(path='/cf/sp007_fill.dat',timeout=5.0)
 before=read_fm_file_info(refresh:false,path:path)
 before_seq=before[:available] ? before[:sequence].to_i : nil
 fm_get_file_info(path)
 wait_until(timeout,0.25) do
  cur=read_fm_file_info(refresh:false,path:path)
  seq_changed=before_seq.nil? || (cur[:available] && cur[:sequence].to_i!=before_seq)
  {matched:(cur[:available] && cur[:filename_matches] && seq_changed),before:before,current:cur}
 end
end

def docker_cpu_percent
 r=shell_capture("docker stats --no-stream --format '{{.CPUPerc}}' #{FSW_CONTAINER} 2>/dev/null | tr -d '%'",timeout_seconds:6)
 txt=r[:stdout].to_s.strip
 ok=r[:ok] && !txt.empty?
 r.merge(ok:ok,cpu_percent:(ok ? txt.to_f : nil),observation:(ok ? 'docker_cpu_available' : 'docker_cli_unavailable_in_operator'))
end
def counter_delta(after,before,key)
 return nil unless after && before && after[:available] && before[:available]
 after[key].to_i-before[key].to_i
end

def wait_until(timeout=6.0,interval=0.2)
 deadline=Time.now+timeout; last=nil
 until Time.now>=deadline
  last=yield; return last.merge(matched:true) if last[:matched]
  sleep interval
 end
 last ? last.merge(matched:false) : {matched:false}
end

def wait_started(profile_id,before,timeout=4.0)
 before_cmd=before[:available] ? before[:cmd_count].to_i : nil
 before_seq=before[:available] ? before[:sequence].to_i : nil
 wait_until(timeout,0.2) do
  cur=read_sp007_hk(refresh:true)
  counter_advanced=before_cmd.nil? || cur[:cmd_count].to_i>before_cmd || cur[:cmd_count].to_i<before_cmd
  fresh_sequence=before_seq.nil? || cur[:sequence].to_i!=before_seq
  profile_seen=cur[:last_profile_id].to_i==profile_id.to_i || cur[:active_profile_id].to_i==profile_id.to_i
  {matched:(cur[:available] && profile_seen && counter_advanced && fresh_sequence),before:before,current:cur,counter_advanced:counter_advanced,fresh_sequence:fresh_sequence,profile_seen:profile_seen}
 end
end

def wait_complete(profile_id,timeout=8.0)
 wait_until(timeout,0.25) do
  cur=read_sp007_hk(refresh:true)
  {matched:(cur[:available] && cur[:last_profile_id].to_i==profile_id.to_i && cur[:active].to_i==0),current:cur}
 end
end

def start_profile(profile,overrides={})
 a=profile.fetch(:args,{}).merge(overrides)
 payload=[profile[:id].to_i,a.fetch(:flags,0).to_i,a.fetch(:duration_ms,0).to_i,a.fetch(:rate_or_yield,0).to_i,a.fetch(:limit,0).to_i,a.fetch(:arg1,0).to_i,a.fetch(:arg2,0).to_i,a.fetch(:arg3,0).to_i,a.fetch(:arg4,0).to_i].pack('v v V V V l< l< l< l<')
 send_udp(command_packet(SP007_CMD_MID,SP007_START_CC,payload)).merge(profile_id:profile[:id],profile_name:profile[:name],args:a)
end

def sp007_noargs(fc); send_udp(command_packet(SP007_CMD_MID,fc,''.b)); end

def cleanup_sp007
 stop=sp007_noargs(SP007_STOP_CC); sleep 0.35; clean=sp007_noargs(SP007_CLEANUP_CC)
 wait=wait_until(4.0,0.25) do
  hk=read_sp007_hk(refresh:true)
  {matched:(hk[:available] && hk[:active].to_i==0 && hk[:held_pipe_count].to_i==0 && hk[:held_queue_count].to_i==0 && hk[:file_present].to_i==0),hk:hk}
 end
 {stop:stop,cleanup:clean,wait:wait}
end

def measure_hk_latency(samples:5,timeout_per_sample:1.5)
 lats=[]; details=[]; read_sp007_hk(refresh:true)
 samples.times do
  before=read_sp007_hk(refresh:false); seq=before[:available] ? before[:sequence].to_i : nil
  t0=Time.now; send=request_sp007_hk
  wait=wait_until(timeout_per_sample,0.03) do
   cur=read_sp007_hk(refresh:false)
   {matched:(cur[:available] && !seq.nil? && cur[:sequence].to_i!=seq),before_sequence:seq,current:cur}
  end
  lat=wait[:matched] ? Time.now-t0 : timeout_per_sample
  lats << lat; details << {send:send,wait:wait,latency_seconds:lat}; sleep 0.12
 end
 sorted=lats.sort; avg=lats.empty? ? nil : lats.sum/lats.length; p95=sorted.empty? ? nil : sorted[[((sorted.length*0.95).ceil-1),sorted.length-1].min]
 {samples:samples,latencies_seconds:lats,avg_seconds:avg,p95_seconds:p95,details:details}
end

def score(verdict:,attack_success:,classification:,safety_meaning:,evidence:,profile:,notes:[])
 {scenario:SCENARIO_ID,profile_id:profile[:id],profile_name:profile[:name],title:profile[:title],expected:profile[:expected],verdict:verdict,attack_success:attack_success,classification:classification,safety_meaning:safety_meaning,evidence:evidence,notes:notes,completed_at:Time.now.utc.iso8601}
end

def hk_delivery_stats(measurement)
 details=Array(measurement[:details])
 matched=details.count{|d| d.dig(:wait,:matched)}
 total=details.length
 timed_out=total-matched
 {samples:total,delivered:matched,timed_out:timed_out,delivery_ratio:(total.positive? ? matched.to_f/total : nil),timeout_ratio:(total.positive? ? timed_out.to_f/total : nil),avg_seconds:measurement[:avg_seconds],p95_seconds:measurement[:p95_seconds]}
end

def require_sp007_live!
 hk=read_sp007_hk(refresh:true)
 raise SkipProfile,'SP007 housekeeping is not live; install, build, launch, and route SP007_HK_TLM before testing.' unless hk[:available]
 hk
end

def verify_cpu(profile)
 c0=cleanup_sp007; before=require_sp007_live!; base=measure_hk_latency(samples:5,timeout_per_sample:1.2); cpu0=docker_cpu_percent
 trig=start_profile(profile); started=wait_started(profile[:id],before,5.0); sleep 0.6
 attack=measure_hk_latency(samples:5,timeout_per_sample:2.0); cpu1=docker_cpu_percent
 events=collect_events(1.5,0.08); done=wait_complete(profile[:id],14.0); final_hk=read_sp007_hk(refresh:true); c1=cleanup_sp007
 b=base[:avg_seconds].to_f; a=attack[:avg_seconds].to_f; ratio=b.positive? ? a/b : nil
 cpu_delta=(cpu1[:cpu_percent].to_f-cpu0[:cpu_percent].to_f if cpu0[:ok] && cpu1[:ok])
 worker_count=[started.dig(:current,:cpu_worker_count).to_i,done.dig(:current,:cpu_worker_count).to_i,(final_hk[:cpu_worker_count] || 0).to_i].max
 expected_workers=profile.fetch(:args,{}).fetch(:arg1,4).to_i
 before_worker_count=before[:available] ? before[:cpu_worker_count].to_i : 0
 worker_count_delta=worker_count-before_worker_count
 completed_successfully=done[:matched] && done.dig(:current,:last_status).to_i==0 && done.dig(:current,:profiles_completed).to_i>=before[:profiles_completed].to_i+1
 trigger_observed=started[:matched] || completed_successfully
 system_latency=ratio && ratio>=1.35 && (a-b)>=0.06
 worker_pressure=worker_count_delta>=4 && (ratio && ratio>=1.20 && (a-b)>=0.03)
 cpu_worker_goal_met=worker_count_delta>=[expected_workers,1].max
 container_cpu=!cpu_delta.nil? && cpu_delta>=20.0
 ev={cleanup_before:c0,trigger:trig,started:started,completed:done,final_hk:final_hk,baseline_latency:base,attack_latency:attack,latency_ratio:ratio,docker_cpu_before:cpu0,docker_cpu_during:cpu1,docker_cpu_delta:cpu_delta,worker_count_observed:worker_count,before_worker_count:before_worker_count,worker_count_delta:worker_count_delta,expected_worker_count:expected_workers,cpu_worker_goal_met:cpu_worker_goal_met,completed_successfully:completed_successfully,trigger_observed:trigger_observed,worker_pressure:worker_pressure,system_latency:system_latency,container_cpu_pressure:container_cpu,events:events,cleanup_after:c1}
 if trigger_observed && (system_latency || worker_pressure || container_cpu)
  score(verdict:'PASS',attack_success:true,classification:'ATTACK_SUCCESS_CPU_PRESSURE_OBSERVED',safety_meaning:'Legal SP007 commands created busy child tasks and caused measurable system-level command/telemetry latency or CPU pressure. Security impact: denial of control risk; commands still exist, but the flight stack has less timing margin to process them.',evidence:ev,profile:profile)
 elsif trigger_observed && cpu_worker_goal_met && completed_successfully
  score(verdict:'FAIL',attack_success:false,classification:'FAIL_PROTECTED_CPU_IMPACT_NOT_OBSERVED',safety_meaning:'SP007 created and completed the requested CPU busy-worker payload, but this run did not show measurable CPU/HK latency degradation. Benchmark result: payload execution alone is not counted as attack success.',evidence:ev,profile:profile,notes:['The worker allocation is retained as payload evidence; PASS requires measured timing/CPU impact.'])
 elsif trigger_observed && worker_count_delta.positive?
  score(verdict:'FAIL',attack_success:false,classification:'OBSERVATION_LIMIT_CPU_EFFECT_NOT_PROVEN',safety_meaning:'SP007 created some CPU busy workers, but the verifier did not observe the requested worker count, successful completion, or enough target-side latency/CPU pressure to prove operational resource exhaustion.',evidence:ev,profile:profile)
 else
  score(verdict:'FAIL',attack_success:false,classification:'FAIL_TRIGGER_OR_SP007_NOT_OBSERVED',safety_meaning:'The resource-exhaustion command was not observed as accepted by the running SP007 app.',evidence:ev,profile:profile)
 end
end

def verify_sb_flood(profile)
 c0=cleanup_sp007; before=require_sp007_live!; f0=read_flood_tlm; sb0=read_sb_hk; st0=read_sb_stats(refresh:true)
 victim_base=measure_hk_latency(samples:8,timeout_per_sample:1.2)
 trig=start_profile(profile); started=wait_started(profile[:id],before,3.0); sleep 0.3
 victim_attack=measure_hk_latency(samples:12,timeout_per_sample:1.2)
 fd=read_flood_tlm; done=wait_complete(profile[:id],20.0); f1=read_flood_tlm; sb1=read_sb_hk; st1=read_sb_stats(refresh:true); logs=docker_logs_since(45); c1=cleanup_sp007
 delta=f1[:available]&&f0[:available] ? f1[:sequence].to_i-f0[:sequence].to_i : nil
 flood_seen=f1[:available] && f1[:profile_id].to_i==profile[:id].to_i && f1[:sequence].to_i.positive?
 count=done.dig(:current,:sb_transmit_count).to_i
 base_stats=hk_delivery_stats(victim_base); attack_stats=hk_delivery_stats(victim_attack)
 base_avg=base_stats[:avg_seconds].to_f; attack_avg=attack_stats[:avg_seconds].to_f
 victim_latency_ratio=base_avg.positive? ? attack_avg/base_avg : nil
 victim_timeout_delta=attack_stats[:timed_out].to_i-base_stats[:timed_out].to_i
 victim_delivery_drop=base_stats[:delivery_ratio] && attack_stats[:delivery_ratio] && attack_stats[:delivery_ratio] < base_stats[:delivery_ratio]
 victim_latency_degraded=victim_latency_ratio && victim_latency_ratio>=1.5 && (attack_avg-base_avg)>=0.10
 victim_impact_observed=victim_timeout_delta>0 || victim_delivery_drop || victim_latency_degraded
 overflow_delta=counter_delta(sb1,sb0,:pipe_overflow_error_count)
 msg_error_delta=counter_delta(sb1,sb0,:msg_send_error_count)
 log_overflow=logs[:stdout].to_s.include?('Pipe Overflow')
 system_drop_observed=(!overflow_delta.nil? && overflow_delta>0) || log_overflow
 ev={cleanup_before:c0,trigger:trig,started:started,completed:done,before_flood_tlm:f0,during_flood_tlm:fd,after_flood_tlm:f1,flood_sequence_delta:delta,before_sb_hk:sb0,after_sb_hk:sb1,before_sb_stats:st0,after_sb_stats:st1,sb_msg_send_error_delta:msg_error_delta,sb_pipe_overflow_delta:overflow_delta,sb_buffer_peak_delta:counter_delta(st1,st0,:peak_sb_buffers_in_use),baseline_victim_hk:base_stats,attack_victim_hk:attack_stats,victim_timeout_delta:victim_timeout_delta,victim_latency_ratio:victim_latency_ratio,victim_impact_observed:victim_impact_observed,system_drop_observed:system_drop_observed,docker_logs:logs,cleanup_after:c1}
 if started[:matched] && flood_seen && system_drop_observed
  score(verdict:'PASS',attack_success:true,classification:'ATTACK_SUCCESS_SB_TO_LAB_DROP_OBSERVED',safety_meaning:'The verifier ran a high-rate SP007 telemetry flood and cFE/TO_LAB reported pipe overflow/drop evidence. Victim HK delivery was measured before and during the flood and retained in evidence. Security impact: untrusted app telemetry can consume downlink queue capacity and cause telemetry loss.',evidence:ev,profile:profile)
 elsif started[:matched] && flood_seen && victim_impact_observed
  score(verdict:'PASS',attack_success:true,classification:'ATTACK_SUCCESS_SB_VICTIM_HK_DEGRADED',safety_meaning:'The verifier observed victim housekeeping delivery/latency degradation during the SP007 telemetry flood. Security impact: untrusted app telemetry can interfere with operational telemetry delivery.',evidence:ev,profile:profile)
 elsif started[:matched] && flood_seen
  score(verdict:'FAIL',attack_success:false,classification:'FAIL_PROTECTED_SB_FLOOD_NO_DROP_OR_VICTIM_IMPACT',safety_meaning:'SP007 flood telemetry reached TO_LAB, but the verifier did not observe cFE/TO_LAB drop evidence or victim HK delivery degradation. Benchmark result: traffic generation alone is not counted as attack success.',evidence:ev,profile:profile)
 elsif started[:matched] && count>=100
  score(verdict:'FAIL',attack_success:false,classification:'OBSERVATION_LIMIT_FLOOD_NOT_ROUTED_TO_GROUND',safety_meaning:'SP007 transmitted many Software Bus messages, but the verifier did not observe routed flood telemetry, downstream drop evidence, or victim HK impact.',evidence:ev,profile:profile)
 else
  score(verdict:'FAIL',attack_success:false,classification:'FAIL_TRIGGER_OR_SB_FLOOD_NOT_OBSERVED',safety_meaning:'The verifier did not observe a successful high-rate Software Bus flood.',evidence:ev,profile:profile)
 end
end

def verify_evs(profile)
 c0=cleanup_sp007; before=require_sp007_live!; log0=docker_logs_since(5,'SP007: EVS storm event')
 trig=start_profile(profile); started=wait_started(profile[:id],before,3.0); events=collect_events(4.0,0.04)
 done=wait_complete(profile[:id],6.0); log1=docker_logs_since(30,'SP007: EVS storm event'); c1=cleanup_sp007
 storm=Array(events[:events]).select{|e| e[:app_name]=='SP007' && e[:message].include?('EVS storm event')}
 squelch=Array(events[:events]).select{|e| e[:app_name]=='CFE_EVS' && e[:message].include?('Events squelched') && e[:message].include?('SP007')}
 distinct=storm.map{|e| e[:event_id]}.uniq.length
 log_lines=log1[:stdout].to_s.lines.count{|l| l.include?('SP007: EVS storm event')}
 evs_count=done.dig(:current,:evs_send_count).to_i
 evs_error_count=done.dig(:current,:evs_send_error_count).to_i
 ev={cleanup_before:c0,trigger:trig,started:started,completed:done,sampled_events:events,sampled_storm_event_count:storm.length,sampled_distinct_event_ids:distinct,sampled_squelch_event_count:squelch.length,evs_send_count:evs_count,evs_send_error_count:evs_error_count,logs_before:log0,logs_after:log1,log_storm_line_count:log_lines,cleanup_after:c1}
 if started[:matched] && (storm.length>=3 || log_lines>=20) && squelch.empty?
  score(verdict:'PASS',attack_success:true,classification:'ATTACK_SUCCESS_EVS_EVENT_STORM_UNCONTAINED',safety_meaning:'The attack drove many legal EVS event sends and the cFE event stream/logs carried the storm without observed EVS squelch containment. Security impact: important events can be delayed or drowned out, turning event/log handling into denial of observability.',evidence:ev,profile:profile)
 elsif started[:matched] && (!squelch.empty? || evs_error_count>=100)
  score(verdict:'FAIL',attack_success:false,classification:'FAIL_PROTECTED_EVS_SQUELCH_CONTAINED',safety_meaning:'CFE_EVS squelch/error behavior contained the SP007 event storm attempt. Benchmark result: most events were suppressed or rejected by EVS, so this is not counted as a successful attack unless broader event loss is independently proven.',evidence:ev,profile:profile)
 elsif started[:matched] && evs_count>=100
  score(verdict:'FAIL',attack_success:false,classification:'OBSERVATION_LIMIT_EVS_OUTPUT_NOT_PROVEN',safety_meaning:'SP007 reports many EVS send calls, but the verifier did not observe enough CFE_EVS_PACKET samples, squelch events, FSW log lines, or broader event loss to prove system-visible event flooding.',evidence:ev,profile:profile)
 else
  score(verdict:'FAIL',attack_success:false,classification:'FAIL_TRIGGER_OR_EVS_STORM_NOT_OBSERVED',safety_meaning:'The verifier did not observe a successful EVS storm profile.',evidence:ev,profile:profile)
 end
end

def verify_cf_fill(profile)
 c0=cleanup_sp007; before=require_sp007_live!; fs0=read_fm_file_info(refresh:true)
 requested_kb=profile.fetch(:args).fetch(:limit).to_i
 trig=start_profile(profile,{limit:requested_kb,duration_ms:profile.fetch(:args).fetch(:duration_ms,30000)})
 started=wait_started(profile[:id],before,3.0); done=wait_complete(profile[:id],60.0); final_hk=read_sp007_hk(refresh:true)
 fs1=wait_fm_file_info('/cf/sp007_fill.dat',8.0); logs=docker_logs_since(90,'SP007|OS_OpenCreate|OS_write|cf|No space|ENOSPC|error|Error|Failed'); c1=cleanup_sp007; cleanup_hk=c1.dig(:wait,:hk); fs2=wait_fm_file_info('/cf/sp007_fill.dat',3.0)
 requested=trig.dig(:args,:limit).to_i*1024
 observed=fs1.dig(:current,:file_size).to_i if fs1.dig(:current,:available)
 before_file_bytes=before[:available] ? before[:file_bytes_written].to_i : 0
 before_file_errors=before[:available] ? before[:file_write_error_count].to_i : 0
 hk_written_abs=[done.dig(:current,:file_bytes_written).to_i,(final_hk[:file_bytes_written] || 0).to_i,cleanup_hk ? cleanup_hk[:file_bytes_written].to_i : 0].max
 file_write_errors_abs=[done.dig(:current,:file_write_error_count).to_i,(final_hk[:file_write_error_count] || 0).to_i,cleanup_hk ? cleanup_hk[:file_write_error_count].to_i : 0].max
 hk_written=[hk_written_abs-before_file_bytes,0].max
 file_write_errors=[file_write_errors_abs-before_file_errors,0].max
 last_api_status=[done.dig(:current,:last_api_status),(final_hk[:last_api_status] if final_hk[:available]),(cleanup_hk[:last_api_status] if cleanup_hk)].compact.map(&:to_i).find{|x| x!=0}
 file_proves=fs1[:matched] && observed && observed >= [requested*0.8,1024*1024].max
 hk_proves=hk_written>=requested*0.8 && (final_hk[:file_present] || 0).to_i==1
 write_error_observed=file_write_errors>0 || logs[:stdout].to_s.match?(/No space|ENOSPC|write.*fail|OS_write/i)
 partial_write_observed=hk_written>0 && hk_written<requested
 storage_impact_proven=write_error_observed || partial_write_observed
 cleanup_removed=fs2.dig(:current,:filename_matches) && fs2.dig(:current,:file_size).to_i==0
 ev={cleanup_before:c0,trigger:trig,started:started,completed:done,final_hk:final_hk,requested_bytes:requested,before_file_info:fs0,after_file_info:fs1,observed_file_size:observed,before_hk_file_bytes_written:before_file_bytes,hk_file_bytes_written_abs:hk_written_abs,hk_file_bytes_written_delta:hk_written,before_file_write_error_count:before_file_errors,file_write_error_count_abs:file_write_errors_abs,file_write_error_count_delta:file_write_errors,last_api_status:last_api_status,hk_file_present_before_cleanup:(final_hk[:file_present] || 0),file_proves:file_proves,hk_proves:hk_proves,write_error_observed:write_error_observed,partial_write_observed:partial_write_observed,storage_impact_proven:storage_impact_proven,docker_logs:logs,cleanup_after:c1,post_cleanup_file_info:fs2,cleanup_removed_or_zero_size:cleanup_removed}
 if started[:matched] && (file_proves || hk_proves)
  score(verdict:'PASS',attack_success:true,classification:'ATTACK_SUCCESS_CF_STORAGE_CONSUMED',safety_meaning:'The verifier confirmed that SP007, an onboard app, created and held a large /cf fill file until cleanup. Security impact: the system did not prevent an app from consuming persistent onboard storage, reducing capacity available for future products, tables, dumps, or logs.',evidence:ev,profile:profile,notes:(storage_impact_proven ? ['Additional storage-impact evidence such as partial write or write error was observed.'] : ['No no-space/write-failure signal was required for this verdict; successful persistent storage consumption before cleanup is the attack effect.']))
 elsif started[:matched] && hk_written>0
  score(verdict:'FAIL',attack_success:false,classification:'OBSERVATION_LIMIT_CF_FILE_NOT_CONFIRMED_BY_FM',safety_meaning:'SP007 reports file writes, but the verifier did not obtain independent FM file-information telemetry or storage-impact evidence.',evidence:ev,profile:profile)
 else
  score(verdict:'FAIL',attack_success:false,classification:'FAIL_STORAGE_WRITE_BLOCKED_OR_NOT_OBSERVED',safety_meaning:'The verifier did not prove that the attack consumed /cf storage; this may indicate write failure before meaningful fill, filesystem protection, or missing FM telemetry.',evidence:ev,profile:profile)
 end
end

def verify_osal(profile)
 c0=cleanup_sp007; before=require_sp007_live!; st0=read_sb_stats(refresh:true); sb0=read_sb_hk
 trig=start_profile(profile); started=wait_started(profile[:id],before,3.0); done=wait_complete(profile[:id],5.0)
 st1=read_sb_stats(refresh:true); sb1=read_sb_hk; logs=docker_logs_since(30,'SP007|CFE_SB|CreatePipe|OS_Queue|pipe|queue|error|Error|Failed')
 c1=cleanup_sp007; st2=read_sb_stats(refresh:true)
 pipe_delta=counter_delta(st1,st0,:pipes_in_use); peak_delta=counter_delta(st1,st0,:peak_pipes_in_use); post_peak_delta=counter_delta(st2,st0,:peak_pipes_in_use); err_delta=counter_delta(sb1,sb0,:create_pipe_error_count); clean_delta=counter_delta(st2,st1,:pipes_in_use)
 held_pipes=done.dig(:current,:held_pipe_count).to_i; held_queues=done.dig(:current,:held_queue_count).to_i
 peak_reached=st2[:available] && st2[:peak_pipes_in_use].to_i>=st2[:max_pipes_allowed].to_i && st2[:max_pipes_allowed].to_i.positive?
 ev={cleanup_before:c0,trigger:trig,started:started,completed:done,before_sb_stats:st0,during_sb_stats:st1,after_cleanup_sb_stats:st2,pipes_in_use_delta:pipe_delta,peak_pipes_in_use_delta:peak_delta,post_cleanup_peak_pipes_in_use_delta:post_peak_delta,peak_pipes_reached_limit:peak_reached,cleanup_pipes_in_use_delta:clean_delta,before_sb_hk:sb0,during_sb_hk:sb1,create_pipe_error_delta:err_delta,held_pipe_count:held_pipes,held_queue_count:held_queues,docker_logs:logs,cleanup_after:c1}
 if started[:matched] && (!pipe_delta.nil? && pipe_delta>=10 || !post_peak_delta.nil? && post_peak_delta>=10 || peak_reached)
  score(verdict:'PASS',attack_success:true,classification:'ATTACK_SUCCESS_IPC_RESOURCE_MARGIN_REDUCED',safety_meaning:'CFE_SB statistics showed pipe resource pressure: pipe usage or peak pipe usage increased, and the system reached the configured pipe limit. Security impact: an onboard app can reduce shared communication resource margin until later legitimate pipe creation fails or recovery apps lose headroom.',evidence:ev,profile:profile)
 elsif started[:matched] && held_pipes.positive?
  score(verdict:'FAIL',attack_success:false,classification:'OBSERVATION_LIMIT_SB_STATS_DID_NOT_MOVE',safety_meaning:'SP007 reports held IPC resources, but CFE_SB statistics did not confirm a current or peak pipe usage increase.',evidence:ev,profile:profile)
 else
  score(verdict:'FAIL',attack_success:false,classification:'FAIL_IPC_RESOURCE_HOLD_NOT_OBSERVED',safety_meaning:'The verifier did not observe the IPC resource exhaustion profile taking effect.',evidence:ev,profile:profile)
 end
end
def verify_profile(profile)
 case profile[:name]
 when 'CPU_BUSY_STARVATION' then verify_cpu(profile)
 when 'SB_TELEMETRY_FLOOD' then verify_sb_flood(profile)
 when 'EVS_EVENT_STORM' then verify_evs(profile)
 when 'CF_STORAGE_FILL' then verify_cf_fill(profile)
 when 'OSAL_QUEUE_EXHAUST' then verify_osal(profile)
 else raise SkipProfile,"No verifier implementation for #{profile[:name]}"
 end
rescue SkipProfile=>e
 score(verdict:'SKIP',attack_success:false,classification:'SKIP_PRECONDITION_NOT_MET',safety_meaning:e.reason,evidence:{error:e.reason},profile:profile)
rescue Exception=>e
 clean=(cleanup_sp007 rescue nil)
 score(verdict:'FAIL',attack_success:false,classification:'FAIL_VERIFIER_ERROR',safety_meaning:'Verifier error prevented a security-relevant conclusion.',evidence:{error_class:e.class.to_s,error:e.message,backtrace:e.backtrace&.first(8),cleanup_after_error:clean},profile:profile)
end

def select_profiles
 return PROFILES if SELECTED.empty?
 wanted=SELECTED.map(&:upcase)
 selected=PROFILES.select{|p| wanted.include?(p[:id].to_s) || wanted.include?(p[:name].upcase)}
 missing=SELECTED.reject{|x| PROFILES.any?{|p| p[:id].to_s==x || p[:name].casecmp?(x)}}
 raise SkipProfile,"Unknown SP007 profile(s): #{missing.join(', ')}" unless missing.empty?
 selected
end

def summarize(scores)
 {scenario:SCENARIO_ID,name:SCENARIO_NAME,generated_at:Time.now.utc.iso8601,report_root:REPORT_ROOT,total:scores.length,pass_attack_success:scores.count{|s| s[:verdict]=='PASS' && s[:attack_success]},fail_protected:scores.count{|s| s[:classification].to_s.start_with?('FAIL_PROTECTED')},observation_limits:scores.count{|s| s[:classification].to_s.start_with?('OBSERVATION_LIMIT')},skips:scores.count{|s| s[:verdict]=='SKIP'},failures:scores.count{|s| s[:verdict]=='FAIL' && !s[:classification].to_s.start_with?('FAIL_PROTECTED') && !s[:classification].to_s.start_with?('OBSERVATION_LIMIT')},scores:scores.map{|s| {profile_id:s[:profile_id],profile_name:s[:profile_name],verdict:s[:verdict],attack_success:s[:attack_success],classification:s[:classification],safety_meaning:s[:safety_meaning]}}}
end

FileUtils.mkdir_p(REPORT_ROOT)
start=Time.now.utc
selected=select_profiles
routes=ensure_routes
sleep 1.0
initial={sp007_hk:read_sp007_hk(refresh:true),sb_hk:read_sb_hk,sb_stats:read_sb_stats(refresh:true),cf_file:cf_file_state,docker_cpu:docker_cpu_percent}

scores=selected.map do |profile|
 result=verify_profile(profile)
 write_profile_score(REPORT_ROOT,result)
 puts "#{result[:profile_name]}: #{result[:verdict]} #{result[:classification]}"
 result
end

summary=summarize(scores).merge(started_at:start.iso8601,routes:routes,initial:initial)
write_json(File.join(REPORT_ROOT,'summary.json'),summary)
puts JSON.pretty_generate(summary)
exit(summary[:failures].positive? ? 1 : 0)
