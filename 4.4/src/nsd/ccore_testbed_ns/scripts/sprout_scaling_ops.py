#!/usr/bin/env python3
import argparse
import logging
import os
import stat
import subprocess
import sys
import time
import yaml
import paramiko
import re
from pexpect import pxssh

'''
{
  config: {
       max_instance_count: 10, 
       min_instance_count: 0, 
       name: sprout_group, scaling_config_action: [
          { ns_config_primitive_name_ref: Sprout Scaling Ops, trigger: pre_scale_in}, 
          { ns_config_primitive_name_ref: Sprout Scaling Ops, trigger: post_scale_out}
       ],
       vnfd_member: [{count: 1, member_vnf_index_ref: 6}]
  }, 
  nsr: {name: NS2}, 
  trigger: post_scale_out,
  vnfrs_in_group: [
       {connection_points: [ {ip_address: 13.0.0.15, name: sprout_vnfd/sigport} ], name: NS2__sprout_group__1__sprout_vnfd__6, 
           rw_mgmt_ip: 10.66.217.196, rw_mgmt_port: 0},
           vdur_data: [{vm_mgmt_ip: 10.0.217.137, vm_name: iovdu_0}]],
  vnfrs_others: [
      {connection_points: [{ip_address: 13.0.0.15, name: sprout_vnfd/sigport}],
          name: NS2__sprout_group__1__sprout_vnfd__6, rw_mgmt_ip: 10.66.217.196, rw_mgmt_port: 0,
          vdur_data: [{vm_mgmt_ip: 10.0.217.130, vm_name: iovdu_0}]}
      {connection_points: [{ip_address: 13.0.0.9, name: dnsserver_vnfd/sigport}], 
          name: NS2__dnsserver_vnfd__5, rw_mgmt_ip: 10.66.217.190, rw_mgmt_port: 0, 
          vdur_data: [{vm_mgmt_ip: 10.0.217.130, vm_name: iovdu_0}]}
      {connection_points: [{ip_address: 13.0.0.10, name: homesteadprov_vnfd/sigport}], 
          name: NS2__homesteadprov_vnfd__1, rw_mgmt_ip: 10.66.217.191, rw_mgmt_port: 0, 
          vdur_data: [{vm_mgmt_ip: 10.0.217.130, vm_name: iovdu_0}]}
      {connection_points: [{ip_address: 13.0.0.11, name: sipp_vnfd/cp0}], name: NS2__sipp_vnfd__4, 
          rw_mgmt_ip: 10.66.217.192, rw_mgmt_port: 2022, 
          vdur_data: [{vm_mgmt_ip: 10.0.217.130, vm_name: iovdu_0}]}
      {connection_points: [ {ip_address: 13.0.0.12, name: homesteadprov_vnfd/sigport}], name: NS2__homesteadprov_vnfd__2,
          rw_mgmt_ip: 10.66.217.193, rw_mgmt_port: 0, 
          vdur_data: [{vm_mgmt_ip: 10.0.217.130, vm_name: iovdu_0}]}
      {connection_points: [{ip_address: 13.0.0.13, name: homesteadprov_vnfd/sigport}], name: NS2__homesteadprov_vnfd__3, 
          rw_mgmt_ip: 10.66.217.194, rw_mgmt_port: 0, 
          vdur_data: [{vm_mgmt_ip: 10.0.217.130, vm_name: iovdu_0}]}
      {connection_points: [{ip_address: 13.0.0.14, name: sprout_vnfd/sigport}], name: NS2__sprout_vnfd__6, 
          rw_mgmt_ip: 10.66.217.195, rw_mgmt_port: 0,
          vdur_data: [{vm_mgmt_ip: 10.0.217.130, vm_name: iovdu_0}]}
           ]}
'''
class ConfigurationError(Exception):
    pass

def copy_file_ssh_sftp(logger, server, username, remote_dir, remote_file, local_file):
    sshclient = paramiko.SSHClient()
    sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    sshclient.load_system_host_keys(filename="/dev/null")
    sshclient.connect(server, username=username, password="fedora")
    sftpclient = sshclient.open_sftp()
    sftpclient.put(local_file, remote_dir + '/' + remote_file)
    sshclient.close()
    logger.debug("Done with copying file %s", local_file)



def get_vnf_file(logger, file_name, d_name, d_id, d_type):
    logger.debug("Obtaining local file %s", file_name)
    # Get the full path to the vnf file
    vnffile = ''
    # If vnf file name name starts with /, assume it is full path
    if file_name[0] == '/':
        # The vnf file name has full path, use as is
        vnffile = file_name
    else:
        vnffile = os.path.join(os.environ['RIFT_ARTIFACTS'],
                                  'launchpad/packages',
                                  d_type,
                                  d_id,
                                  d_name,
                                  'scripts',
                                  file_name)
        logger.debug("Checking for vnf file name at %s", vnffile)
        if not os.path.exists(vnffile):
            logger.debug("Did not find file %s", vnffile)
            vnffile = os.path.join(os.environ['RIFT_INSTALL'],
                                      'usr/bin',
                                      file_name)
    return vnffile

def configure_sippscaleop(logger, run_dir, vnf_mgmt_ip, sipp_sig_ip, dns_vm_ip):
    logger.debug("Starting SIPP scaleop ")

    num_sprouts = 0   
    sipp_local_port = 5060
    try:
       sess = pxssh.pxssh(options={
                    "StrictHostKeyChecking": "no",
                    "UserKnownHostsFile": "/dev/null"})
       sess.login(vnf_mgmt_ip, "fedora", "fedora")
       sess.timeout = 60

       # Find number of SIPPs
       cmd_str = "dig @{} -t A sprout.test.com +noall +answer".format(dns_vm_ip)
       sess.sendline(cmd_str)   # run a command
       sess.prompt()
       dnsresults = str(sess.before)
       logger.debug("DNS results %s", dnsresults)        # print everything before the prompt.
       ipv4_pattern = "\d+\.\d+\.\d+\.\d+"
       matchlist = re.findall(ipv4_pattern, dnsresults)
       sproutlist = list()
       for sproutip in matchlist:
           if sproutip != dns_vm_ip:
               num_sprouts += 1
               sproutlist.append(sproutip)
       logger.debug("Num sprouts %s", num_sprouts)

       # Obtain cumulative call-rate for old SIPPs
       sess.sendline("ps -ef | grep sipp-master")
       sess.prompt()
       sipp_process_output = str(sess.before)
       matchlist = re.findall("r\s+\d+\s+", sipp_process_output)
       logger.debug("Callrate matchlist %s", matchlist)
       if matchlist == []:
          sess.logout
          return
       # Calculate cumulative call rate of all existing sipp clients
       cumul_callrate = 0
       for callratestr in matchlist:
           callrate = 0
           # Each is of the pattern 'r 2 '
           match = re.search("\d+", callratestr)
           if match:
              callrate = int(match.group(0))
           logger.debug("Individual call rate is %s", callrate)
           cumul_callrate += callrate
 
       logger.debug("Cumulative call rate is %s", cumul_callrate)
       sess.sendline("pkill sipp-master")   # run a command
       sess.prompt()
       sess.sendline("rm -f /tmp/sipp_stats*.txt")   # run a command
       sess.prompt()

       per_sipp_call_rate = int(int(cumul_callrate)/num_sprouts)
       filectr = 1
       for sproutip in sproutlist :
           cmd_str = "./sipp-master -sf reg_auth_dereg.xml -inf data1.csv -i {sipp_sig_ip} -p {sipp_local_port} -key registrar test.com -l 0 -r {per_sipp_call_rate} -t t1 {sproutip}:5052 -trace_stat -stf /tmp/sipp_stats{filectr}.txt -bg -fd 20\r".format(sipp_sig_ip=sipp_sig_ip, sipp_local_port=sipp_local_port, per_sipp_call_rate=per_sipp_call_rate, sproutip=sproutip, filectr=filectr)
           logger.debug("Starting %s", cmd_str)
           sess.sendline(cmd_str)
           sess.prompt()
           sipp_local_port += 1
           filectr += 1
           logger.debug("Started sipp for %s", sproutip)
      
       sess.logout()

    except Exception as e:
       logger.exception("Exception seen while starting sipp traffic %s", str(e))
       raise
    
    logger.debug("Finished start/stop  SIPP scenario ")

'''     
     script to configure DNS server for Sprout Scaleout
  '''
def configure_dnsserver_sproutscaleout(logger, run_dir, dns_vnf_mgmt_ip, dns_vm_mgmt_ip, sproutinfo):
      sh_file = "{}/configure_dnsserver-sproutscaleout{}.sh".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
      logger.debug("Creating DNS server script file %s", sh_file)
      with open(sh_file, "w") as f:
          f.write(r'''#!/usr/bin/expect -f
  set login "fedora"
  set pw "fedora"
  set success 0
  spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $login@{vnf_mgmt_ip}
  set spid $spawn_id
  set timeout 60 
  
  expect -i $spid \
                    "*?assword:"      {{
                                  exp_send -i $spid "$pw\r"
                                  if {{ $success == 0 }} {{
                                          incr success -1
                                          exp_continue
                                  }}
                  }} "]$ "  {{
                          set success 1
                  }} "yes/no"      {{
                          exp_send -i $spid "yes\r"
                          exp_continue
                  }} timeout       {{
                          set success -1
                  }}
          
  send "sudo su\r"
  expect "]# "
      
  set sproutmgmtname {sprout_mgmt_name}
  set sproutmgmtname2  [string map {{"_" ""}} $sproutmgmtname]
  set sproutsigname {sprout_sig_name}
  set sproutsigname2  [string map {{"_" ""}} $sproutsigname]
  
  send "sed -i '/# Management A records/a local-data: \"$sproutmgmtname2.test.com. IN A {sprout_mgmt_ip}\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "sed -i '/# A records for individual Clearwater nodes/a local-data: \"$sproutsigname2.test.com. IN A {sprout_sig_ip}\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "sed -i '/# A record load-balancing/a local-data: \"sprout.test.com. IN A {sprout_sig_ip}\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "sed -i '/# A record load-balancing/a local-data: \"sprout-mgmt.test.com. IN A {sprout_mgmt_ip}\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "

  send "sed -i '/# A record load-balancing/a local-data: \"icscf.sprout.test.com. IN A {sprout_sig_ip}\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "sed -i '/# S-CSCF cluster/a local-data: \"_sip._udp.sprout.test.com. IN SRV 0 0 5054 $sproutsigname2.test.com.\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "sed -i '/# S-CSCF cluster/a local-data: \"_sip._tcp.sprout.test.com. IN SRV 0 0 5054 $sproutsigname2.test.com.\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "sed -i '/# S-CSCF cluster/a local-data: \"_sip._udp.scscf.sprout.test.com. IN SRV 0 0 5054 $sproutsigname2.test.com.\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "sed -i '/# S-CSCF cluster/a local-data: \"_sip._tcp.scscf.sprout.test.com. IN SRV 0 0 5054 $sproutsigname2.test.com.\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  
  send "sed -i '/# I-CSCF cluster/a local-data: \"_sip._tcp.icscf.sprout.test.com. IN SRV 0 0 5052 $sproutsigname2.test.com.\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "sed -i '/# I-CSCF cluster/a local-data: \"_sip._udp.icscf.sprout.test.com. IN SRV 0 0 5052 $sproutsigname2.test.com.\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "sed -i '/# Reverse lookups for individual nodes/a local-data-ptr: \"{sprout_mgmt_ip} $sproutmgmtname2.test.com\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "sed -i '/# Reverse lookups for individual nodes/a local-data-ptr: \"{sprout_sig_ip} $sproutsigname2.test.com\"' /etc/unbound/local.d/test.com.conf\r"
  expect "]# "

  send "cat /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "service unbound restart\r"
  expect "]# "
  sleep 5
  
  exp_close -i $spid
  '''.format(vnf_mgmt_ip=dns_vnf_mgmt_ip, vm_mgmt_ip=dns_vm_mgmt_ip, sprout_mgmt_name=sproutinfo['mgmt_name'], sprout_mgmt_ip=sproutinfo['local_mgmt_ip'], sprout_sig_name=sproutinfo['sig_name'], sprout_sig_ip=sproutinfo['sig_ip']))
  
      os.chmod(sh_file, stat.S_IRWXU)
      cmd = "{sh_file}".format(sh_file=sh_file)
      logger.debug("Executing shell cmd : %s", cmd)
      rc = subprocess.call(cmd, shell=True)
      if rc != 0:
          raise ConfigurationError("Configuration of DNS entries in {} failed: {}".format(dns_vnf_mgmt_ip, rc))

'''
     script to configure sprout VNf for scale-out operation
'''     
def configure_sproutscaleout(logger, run_dir, vnf_mgmt_ip, vm_mgmt_ip, dns_mgmt_ip, dns_sig_ip, etcd_ip, sprout_mgmt_name):
      sh_file = "{}/configure_sproutscaleout-{}.sh".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
      logger.debug("Creating sprout script file %s", sh_file)
      with open(sh_file, "w") as f:
          f.write(r'''#!/usr/bin/expect -f
  set login "clearwater"
  set pw "!clearwater"
  set success 0
  spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $login@{vnf_mgmt_ip}
  set spid $spawn_id
  set timeout 60
  
  expect -i $spid \
                    "*?assword:"      {{
                                  exp_send -i $spid "$pw\r"
                                  if {{ $success == 0 }} {{
                                          incr success -1
                                          exp_continue
                                  }}
                  }} "~$ "  {{
                          set success 1
                  }} "yes/no"      {{
                          exp_send -i $spid "yes\r"
                          exp_continue
                  }} timeout       {{
                          set success -1
                  }}
  
  send "sudo su\r"
  expect "clearwater# "
  
          # Rename Host
        set sproutname {sprout_mgmt_name}
        set sproutname2  [string map {{"_" ""}} $sproutname]
        send "echo $sproutname2.test.com > /etc/hostname\r"
        expect "clearwater# "
        send "hostname -F /etc/hostname\r"
        expect "clearwater# "

        # Update /etc/hosts if needed
        send "TMPHOSTS=/etc/hosts.rift.new\r"
        expect "clearwater# "
        send "grep -v '127\[.\]0\[.\]1\[.\]1\[\[:space:\]\]' < /etc/hosts > \$TMPHOSTS\r"
        expect "clearwater# "
        send "mv \$TMPHOSTS /etc/hosts\r"
        expect "clearwater# "

        # Recreate SSH2 keys
        send "export DEBIAN_FRONTEND=noninteractive\r"
        expect "clearwater# "
        send "dpkg-reconfigure openssh-server\r"
        expect "clearwater# "

        # Remove DHCP exit hook
        send "mv /etc/dhcp/dhclient-exit-hooks.d/sethostname /tmp/sethostname.bkup\r"
        expect "clearwater# "

        # Update clearwater local config
        send "sed -iE 's/public_hostname=.*/public_hostname=$sproutname2.test.com/' /etc/clearwater/local_config\r"
        expect "clearwater# "

        # Debug
        send "cat /etc/clearwater/local_config\r"
        expect "clearwater# "

  # Update ETCD cluster clearwater local config
  send "sed -iE 's/etcd_cluster=.*/etcd_cluster={etcd_ip}/' /etc/clearwater/local_config\r"
  expect "clearwater# "
  # Update signaling dns server
  send "sed -iE 's/signaling_dns_server=.*/signaling_dns_server={dns_sig_ip}/' /etc/clearwater/local_config\r"
  expect "clearwater# "
  # Update /etc/resolv.conf
  send "echo 'nameserver {dns_mgmt_ip}' > /etc/resolv.conf\r"
  expect "clearwater# "
  send "echo 'search test.com' >> /etc/resolv.conf\r"
  expect "clearwater# "
  # Update /etc/netns/signaling/resolv.conf 
  send "echo 'nameserver {dns_sig_ip}' > /etc/netns/signaling/resolv.conf \r"
  expect "clearwater# "
  
  
  # Debug
  send "cat /etc/clearwater/local_config\r"
  expect "clearwater# "
  send "cat /etc/clearwater/shared_config\r"
  expect "clearwater# "

  # Start services
  send "service clearwater-infrastructure restart\r"
  expect "clearwater# "
  send "service sprout restart\r"
  expect "clearwater# "

  # Waiting for etcd cluster to sync
  puts "Sleeping for 2 min"
  sleep 60
  puts "Sleeping for 1 more min"
  sleep 60
  # Debug
  send "cat /etc/clearwater/local_config\r"
  expect "clearwater# "
  send "cat /etc/clearwater/shared_config\r"
  expect "clearwater# "
  
  
  exp_close -i $spid
  '''.format(vnf_mgmt_ip=vnf_mgmt_ip, vm_mgmt_ip=vm_mgmt_ip, dns_mgmt_ip=dns_mgmt_ip, dns_sig_ip=dns_sig_ip, etcd_ip=etcd_ip, sprout_mgmt_name=sprout_mgmt_name))
  
      os.chmod(sh_file, stat.S_IRWXU)
      cmd = "{sh_file}".format(sh_file=sh_file)
      logger.debug("Executing shell cmd : %s", cmd)
      rc = subprocess.call(cmd, shell=True)
      if rc != 0:
          raise ConfigurationError("Configuration of {} failed: {}".format(vnf_mgmt_ip, rc))

''' 
     script to configure DNS server for Sprout Scalein
  '''
def configure_dnsserver_sproutscalein(logger, run_dir, dns_vnf_mgmt_ip, dns_vm_mgmt_ip, sproutinfo):
      sh_file = "{}/configure_dnsserver-sproutscalein{}.sh".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
      logger.debug("Creating DNS server script file %s", sh_file)
      with open(sh_file, "w") as f:
          f.write(r'''#!/usr/bin/expect -f
  set login "fedora"
  set pw "fedora"
  set success 0
  spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $login@{vnf_mgmt_ip}
  set spid $spawn_id
  set timeout 60 
  
  expect -i $spid \
                    "*?assword:"      {{
                                  exp_send -i $spid "$pw\r"
                                  if {{ $success == 0 }} {{
                                          incr success -1
                                          exp_continue
                                  }}
                  }} "]$ "  {{
                          set success 1
                  }} "yes/no"      {{
                          exp_send -i $spid "yes\r"
                          exp_continue
                  }} timeout       {{
                          set success -1
                  }}
          
  send "sudo su\r"
  expect "]# "
      
  set sproutmgmtname {sprout_mgmt_name}
  set sproutmgmtname2  [string map {{"_" ""}} $sproutmgmtname]
  set sproutsigname {sprout_sig_name}
  set sproutsigname2  [string map {{"_" ""}} $sproutsigname]
  set sproutmgmtip {sprout_mgmt_ip}
  set sproutsigip {sprout_sig_ip}

  send "sed -i '/$sproutsigname2/d'  /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "sed -i '/$sproutmgmtip/d'  /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "sed -i '/$sproutsigip/d'  /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "cat /etc/unbound/local.d/test.com.conf\r"
  expect "]# "
  
  send "service unbound restart\r"
  expect "]# "
  sleep 5
  
  exp_close -i $spid
  '''.format(vnf_mgmt_ip=dns_vnf_mgmt_ip, vm_mgmt_ip=dns_vm_mgmt_ip, sprout_mgmt_name=sproutinfo['mgmt_name'], sprout_mgmt_ip=sproutinfo['local_mgmt_ip'], sprout_sig_name=sproutinfo['sig_name'], sprout_sig_ip=sproutinfo['sig_ip']))

      os.chmod(sh_file, stat.S_IRWXU)
      cmd = "{sh_file}".format(sh_file=sh_file)
      logger.debug("Executing shell cmd : %s", cmd)
      rc = subprocess.call(cmd, shell=True)
      if rc != 0:
          raise ConfigurationError("Configuration of DNS entries in {} failed: {}".format(dns_vnf_mgmt_ip, rc))



'''
     script to configure sprout VNf for scale-out operation
'''
def configure_sproutscalein(logger, run_dir, vnf_mgmt_ip, vm_mgmt_ip, dns_mgmt_ip, dns_sig_ip, etcd_ip, sprout_mgmt_name):
      sh_file = "{}/configure_sproutscalein-{}.sh".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
      logger.debug("Creating sprout script file %s", sh_file)
      with open(sh_file, "w") as f:
          f.write(r'''#!/usr/bin/expect -f
  set login "clearwater"
  set pw "!clearwater"
  set success 0
  spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $login@{vnf_mgmt_ip}
  set spid $spawn_id
  set timeout 120
  
  expect -i $spid \
                    "*?assword:"      {{
                                  exp_send -i $spid "$pw\r"
                                  if {{ $success == 0 }} {{
                                          incr success -1
                                          exp_continue
                                  }}
                  }} "~$ "  {{
                          set success 1
                  }} "yes/no"      {{
                          exp_send -i $spid "yes\r"
                          exp_continue
                  }} timeout       {{
                          set success -1
                  }}
  
  send "sudo su\r"
  expect "clearwater# "
  
  send "monit unmonitor -g sprout\r"
  expect "clearwater# "

  send "service sprout quiesce\r"
  expect "clearwater# "

  send "monit unmonitor clearwater_cluster_manager\r"
  expect "clearwater# "

  send "monit unmonitor clearwater_config_manager\r"
  expect "clearwater# "

  send "monit unmonitor clearwater_queue_manager_process\r"
  expect "clearwater# "

  send "monit unmonitor -g etcd\r"
  expect "clearwater# "

  send "service clearwater-etcd decommission\r"
  expect "clearwater# "

  exp_close -i $spid
  '''.format(vnf_mgmt_ip=vnf_mgmt_ip, vm_mgmt_ip=vm_mgmt_ip, dns_mgmt_ip=dns_mgmt_ip, dns_sig_ip=dns_sig_ip, etcd_ip=etcd_ip, sprout_mgmt_name=sprout_mgmt_name))

      os.chmod(sh_file, stat.S_IRWXU)
      cmd = "{sh_file}".format(sh_file=sh_file)
      logger.debug("Executing shell cmd : %s", cmd)
      rc = subprocess.call(cmd, shell=True)
      if rc != 0:
          raise ConfigurationError("Configuration of {} failed: {}".format(vnf_mgmt_ip, rc))

def main(argv=sys.argv[1:]):
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("yaml_cfg_file", type=argparse.FileType('r'))
        parser.add_argument("--quiet", "-q", dest="verbose", action="store_false")
        args = parser.parse_args()

        run_dir = os.path.join(os.environ['RIFT_INSTALL'], "var/run/rift")
        if not os.path.exists(run_dir):
            os.makedirs(run_dir)
        log_file = "{}/sprout-scaling-ops-{}.log".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
        logging.basicConfig(filename=log_file, level=logging.DEBUG)
        logger = logging.getLogger()

        ch = logging.StreamHandler()
        if args.verbose:
            ch.setLevel(logging.DEBUG)
        else:
            ch.setLevel(logging.INFO)

        # create formatter and add it to the handlers
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    except Exception as e:
        print("Got exception:{}".format(e))
        raise

    try:
        yaml_str = args.yaml_cfg_file.read()
        logger.debug("Input YAML file: %s", yaml_str)
        yaml_cfg = yaml.load(yaml_str)
        logger.debug("Input YAML cfg: %s", yaml_cfg)

        def find_vnfr(vnfr_list, vnfd_name):
            for vnfr in vnfr_list:
                if vnfd_name in vnfr['name']:
                    return vnfr

            raise ValueError("Could not find vnfd %s", vnfd_name)

        def find_vnfr_mbr_id(vnfr_list, mbr_id):
            for vnfr in vnfr_list:
                if vnfr['member_vnf_index_ref'] == mbr_id:
                    return vnfr

            raise ValueError("Could not find vnfd %s", mbr_id)

        def find_cp_ip(vnfr, cp_name):
            for cp in vnfr['connection_points']:
               logger.debug("Connection point: %s", format(cp))
               if cp_name in cp['name']:
                  return cp['ip_address']

            raise ValueError("Could not find vnfd %s connection point %s", cp_name)

        # This is temporary. All this data should come from VLR
        def get_ipv4_subnet(vnfr, cp_name):
            for cp in vnfr['connection_point']:
               logger.debug("Connection point: %s", format(cp))
               if cp_name in cp['name']:
                  nw = cp['ip_address'].split(".")
                  subnet = nw[0]+"."+nw[1]+"."+nw[2]+".0/24"
                  return subnet

            raise ValueError("Could not find vnfd %s connection point %s", cp_name)

        def find_vnfr_mgmt_ip(vnfr):
            return vnfr['rw_mgmt_ip']

        def find_vdur_mgmt_ip(vnfr):
            return vnfr['vdur_data'][0]['vm_mgmt_ip']

        def find_param_value(param_list, input_param):
            for item in param_list:
               logger.debug("Parameter: %s", format(item))
               if item['name'] == input_param:
                  return item['value']

        def get_vnfr_name(vnfr):
            return vnfr['name']

        trigger = yaml_cfg['trigger']
        dns_info = dict()
        dns_vnfr = find_vnfr(yaml_cfg['vnfrs_others'], "dnsserver_vnfd")
        dns_info['floating_mgmt_ip'] = find_vnfr_mgmt_ip(dns_vnfr)
        dns_info['local_mgmt_ip'] = find_vdur_mgmt_ip(dns_vnfr)
        dns_info['sig_ip'] = find_cp_ip(dns_vnfr, 'dnsserver_vnfd/sigport')

        hs1_vnfr = find_vnfr_mbr_id(yaml_cfg['vnfrs_others'], 1)
        etcd_ip = find_vdur_mgmt_ip(hs1_vnfr)

        sprout_info = dict()
        sprout_vnfr = find_vnfr(yaml_cfg['vnfrs_in_group'], "sprout_vnfd")
        sprout_vnf_name = get_vnfr_name(sprout_vnfr)
        sprout_info['mgmt_name'] = sprout_vnf_name + "-mgmt"
        sprout_info['sig_name'] = sprout_vnf_name
        sprout_info['floating_mgmt_ip'] = find_vnfr_mgmt_ip(sprout_vnfr)
        sprout_info['local_mgmt_ip'] = find_vdur_mgmt_ip(sprout_vnfr)
        sprout_info['sig_ip'] = find_cp_ip(sprout_vnfr, 'sprout_vnfd/sigport')

        sprout_list = []
        sprout_list.append(sprout_info)


        sipp_info = dict()
        sipp_vnfr = find_vnfr(yaml_cfg['vnfrs_others'], "sipp_vnfd")
        sipp_vnf_name = get_vnfr_name(sipp_vnfr)
        sipp_info['mgmt_name'] = sipp_vnf_name + "-mgmt"
        sipp_info['sig_name'] = sipp_vnf_name
        sipp_info['floating_mgmt_ip'] = find_vnfr_mgmt_ip(sipp_vnfr)
        sipp_info['local_mgmt_ip'] = find_vdur_mgmt_ip(sipp_vnfr)
        sipp_info['sig_ip'] = find_cp_ip(sipp_vnfr, 'sipp_vnfd/cp0')

        if yaml_cfg['trigger'] == 'post_scale_out':
            logger.debug("Waiting for 30 secs for VNF to boot up.")
            time.sleep(30)
            logger.debug("Configuring DNS server VNF for sprout scaleout")
            configure_dnsserver_sproutscaleout(logger, run_dir, dns_info['floating_mgmt_ip'], dns_info['local_mgmt_ip'], sprout_info)
            logger.debug("Configuring Sprout VNF scaleout")
            configure_sproutscaleout(logger, run_dir, sprout_info['floating_mgmt_ip'], sprout_info['local_mgmt_ip'], dns_info['local_mgmt_ip'], dns_info['sig_ip'], etcd_ip, sprout_info['mgmt_name'])
            logger.debug("Configuring SIPP VNF to start another client..")
            configure_sippscaleop(logger, run_dir, sipp_info['floating_mgmt_ip'], sipp_info['local_mgmt_ip'], dns_info['local_mgmt_ip'])
        elif yaml_cfg['trigger'] == 'pre_scale_in':
            logger.debug("Configuring DNS server VNF for sprout scalein..")
            configure_dnsserver_sproutscalein(logger, run_dir, dns_info['floating_mgmt_ip'], dns_info['local_mgmt_ip'], sprout_info)
            logger.debug("Configuring SIPP VNF to stop one client..")
            configure_sippscaleop(logger, run_dir, sipp_info['floating_mgmt_ip'], sipp_info['local_mgmt_ip'], dns_info['local_mgmt_ip'])
            logger.debug("Configuring sprout for scalein")
            configure_sproutscalein(logger, run_dir, sprout_info['floating_mgmt_ip'], sprout_info['local_mgmt_ip'], dns_info['local_mgmt_ip'], dns_info['sig_ip'], etcd_ip, sprout_info['mgmt_name'])
        else:
            raise ValueError("Unexpected trigger {}".format(yaml_cfg['trigger']))
        logger.debug("Done with scaling config")


    except Exception as e:
        logger.exception(e)
        raise

if __name__ == "__main__":
    main()
