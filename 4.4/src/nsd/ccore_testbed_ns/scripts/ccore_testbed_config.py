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
from pexpect import pxssh

'''
config-agent: {}
nsr_name: ccore_testbed_nsd
parameter: {}
vnfr:
  1:
    connection_point:
    - ip_address: 14.0.0.4
      name: homesteadprov_vnfd/sigport
    mgmt_ip_address: 10.66.113.180
    mgmt_port: 0
    name: NS1__homesteadprov_vnfd__1
    vdur:
    - id: 723aff17-7e10-423f-8780-28b6287608d2
      management_ip: 10.66.113.180
      name: iovdu_0
      vm_management_ip: 10.0.113.16
  2:
    connection_point:
    - ip_address: 14.0.0.3
      name: homesteadprov_vnfd/sigport
    mgmt_ip_address: 10.66.113.178
    mgmt_port: 0
    name: NS1__homesteadprov_vnfd__2
    vdur:
    - id: 10684c1d-13fc-4164-a6d0-381ac725f85c
      management_ip: 10.66.113.178
      name: iovdu_0
      vm_management_ip: 10.0.113.15
  3:
    connection_point:
    - ip_address: 14.0.0.5
      name: homesteadprov_vnfd/sigport
    mgmt_ip_address: 10.66.113.181
    mgmt_port: 0
    name: NS1__homesteadprov_vnfd__3
    vdur:
    - id: 84c3f536-a56a-4040-ac39-152574397300
      management_ip: 10.66.113.181
      name: iovdu_0
      vm_management_ip: 10.0.113.18
  4:
    connection_point:
    - ip_address: 14.0.0.2
      name: sipp_vnfd/cp0
    mgmt_ip_address: 10.66.113.177
    mgmt_port: 2022
    name: NS1__sipp_vnfd__4
    vdur:
    - id: 85035b3b-14b5-4f61-a943-66b0e1ef858a
      management_ip: 10.66.113.177
      name: iovdu
      vm_management_ip: 10.0.113.14
  5:
    mgmt_ip_address: 10.66.113.179
    mgmt_port: 0
    name: NS1__dnsserver_vnfd__5
    vdur:
    - id: 4f365a48-49b5-44c0-b38d-50113ddc7fa4
      management_ip: 10.66.113.179
      name: iovdu_0
      vm_management_ip: 10.0.113.17
  6:
    connection_point:
    - ip_address: 14.0.0.6
      name: sprout_vnfd/sigport
    mgmt_ip_address: 10.66.113.182
    mgmt_port: 0
    name: NS1__sprout_vnfd__6
    vdur:
    - id: 604895c1-a7fe-4341-90d6-9a1c5b56dabd
      management_ip: 10.66.113.182
      name: iovdu_0
      vm_management_ip: 10.0.113.19
vnfr_name: NS1__dnsserver_vnfd__5
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
    logger.debug("Done witth copying %s", local_file)


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

'''
   script to configure DNS server
'''
def configure_dnsserver_hsentries(logger, run_dir, dns_vnf_mgmt_ip, dns_vm_mgmt_ip, hsinfo):
    sh_file = "{}/configure_dnsserver-hsentries{}.sh".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
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

set hsmgmtname {hs_mgmt_name}
set hsmgmtname2  [string map {{"_" ""}} $hsmgmtname]
set hssigname {hs_sig_name}
set hssigname2  [string map {{"_" ""}} $hssigname]
send "sed -i '/# Management A records/a local-data: \"$hsmgmtname2.test.com. IN A {hs_mgmt_ip}\"' /etc/unbound/local.d/test.com.conf\r"
expect "]# "

send "sed -i '/# A records for individual Clearwater nodes/a local-data: \"$hssigname2.test.com. IN A {hs_sig_ip}\"' /etc/unbound/local.d/test.com.conf\r"
expect "]# "

send "sed -i '/# A record load-balancing/a local-data: \"homestead.test.com. IN A {hs_sig_ip}\"' /etc/unbound/local.d/test.com.conf\r"
expect "]# "

send "sed -i '/# A record load-balancing/a local-data: \"homestead-mgmt.test.com. IN A {hs_mgmt_ip}\"' /etc/unbound/local.d/test.com.conf\r"
expect "]# "

send "sed -i '/# Reverse lookups for individual nodes/a local-data-ptr: \"{hs_mgmt_ip} $hsmgmtname2.test.com\"' /etc/unbound/local.d/test.com.conf\r"
expect "]# "

send "sed -i '/# Reverse lookups for individual nodes/a local-data-ptr: \"{hs_sig_ip} $hssigname2.test.com\"' /etc/unbound/local.d/test.com.conf\r"
expect "]# "

send "cat /etc/unbound/local.d/test.com.conf\r"
expect "]# "

sleep 2

exp_close -i $spid
'''.format(vnf_mgmt_ip=dns_vnf_mgmt_ip, vm_mgmt_ip=dns_vm_mgmt_ip, hs_mgmt_name=hsinfo['mgmt_name'], hs_mgmt_ip=hsinfo['local_mgmt_ip'], hs_sig_name=hsinfo['sig_name'], hs_sig_ip=hsinfo['sig_ip']))

    os.chmod(sh_file, stat.S_IRWXU)
    cmd = "{sh_file}".format(sh_file=sh_file)
    logger.debug("Executing shell cmd : %s", cmd)
    rc = subprocess.call(cmd, shell=True)
    if rc != 0:
        raise ConfigurationError("Configuration of DNS entries in {} failed: {}".format(dns_vnf_mgmt_ip, rc))

'''
   script to configure DNS server
'''
def configure_dnsserver_sproutentries(logger, run_dir, dns_vnf_mgmt_ip, dns_vm_mgmt_ip, sproutinfo):
    sh_file = "{}/configure_dnsserver-sproutentries{}.sh".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
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

send "sed -i '/# Management A records/a local-data: \"sas.test.com. IN A 10\.0\.202\.236\"' /etc/unbound/local.d/test.com.conf\r"
expect "]# "

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

send "echo /# S-CSCF cluster/a local-data: \'sprout.test.com. IN NAPTR 10 100 \"s\" \"SIP+D2T\" \"\"  _sip._tcp.scscf.sprout.test.com.\' > /tmp/sed1.txt\r"
expect "]# "
send "sed -i -f /tmp/sed1.txt /etc/unbound/local.d/test.com.conf \r"
expect "]# "


send "sed -i '/# I-CSCF cluster/a local-data: \"_sip._tcp.icscf.sprout.test.com. IN SRV 0 0 5052 $sproutsigname2.test.com.\"' /etc/unbound/local.d/test.com.conf\r"
expect "]# "

send "sed -i '/# I-CSCF cluster/a local-data: \"_sip._udp.icscf.sprout.test.com. IN SRV 0 0 5052 $sproutsigname2.test.com.\"' /etc/unbound/local.d/test.com.conf\r"
expect "]# "

send "echo /# I-CSCF cluster/a local-data: \'sprout.test.com. IN NAPTR 10 100 \"s\" \"SIP+D2T\" \"\"  _sip._tcp.icscf.sprout.test.com.\' > /tmp/sed2.txt\r"
expect "]# "
send "sed -i -f /tmp/sed2.txt /etc/unbound/local.d/test.com.conf \r"
expect "]# "

send "sed -i '/# Reverse lookups for individual nodes/a local-data-ptr: \"{sprout_mgmt_ip} $sproutmgmtname2.test.com\"' /etc/unbound/local.d/test.com.conf\r"
expect "]# "

send "sed -i '/# Reverse lookups for individual nodes/a local-data-ptr: \"{sprout_sig_ip} $sproutsigname2.test.com\"' /etc/unbound/local.d/test.com.conf\r"
expect "]# "

# Add beginnning quote
send "sed -i \"s/local-data: sprout.test.com./local-data: \'sprout.test.com./g\" /etc/unbound/local.d/test.com.conf \r"
expect "]# "
# Add end quote
send "sed -i \"s/cscf.sprout.test.com.$/cscf.sprout.test.com.\'/\" /etc/unbound/local.d/test.com.conf \r"
expect "]# "
send "cat /etc/unbound/local.d/test.com.conf\r"
expect "]# "

send "service unbound start\r"
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
   script to configure homestead1 VNf
'''
def configure_hs(logger, run_dir, vnf_mgmt_ip, dns_mgmt_ip, dns_sig_ip, etcd_ip, shared_config_exists=False):
    sh_file = "{}/configure_hs-{}.sh".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
    logger.debug("Creating homestead script file %s", sh_file)
    with open(sh_file, "w") as f:
        f.write(r'''#!/usr/bin/expect -f
set login "clearwater"
set pw "!clearwater"
set success 0
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $login@{vnf_mgmt_ip}
set spid $spawn_id
set timeout 60

if {{[llength $argv] != 1}} {{
    send_user "Usage: configure_hs <shared_config_exists> \n"
    exit 1
}}

set shared_config_exists [lindex $argv 0]

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

if {{ $shared_config_exists eq "False" }} {{
   # Comment out billing realm
   send "sed -iE 's/billing_realm=/#billing_realm/' /etc/clearwater/shared_config\r"
   expect "clearwater# "
   # Comment out snmp
   send "sed -iE 's/snmp_ip=/#snmp_ip=/' /etc/clearwater/shared_config\r"
   expect "clearwater# "
   # Change openstacklocal to test.com
   send "sed -iE 's/openstacklocal/test.com/' /etc/clearwater/shared_config\r"
   expect "clearwater# "
   # Update HS provisioning host name
   send "sed -iE 's/hs_provisioning_hostname=.*/hs_provisioning_hostname=homestead-mgmt.test.com:8889/' /etc/clearwater/shared_config\r"
   expect "clearwater# "

}}


# Debug
send "cat /etc/clearwater/local_config\r"
expect "clearwater# "
send "cat /etc/clearwater/shared_config\r"
expect "clearwater# "

# Start services
send "service clearwater-infrastructure restart\r"
expect "clearwater# "
send "service homestead restart && service homestead-prov restart\r"
expect "clearwater# "

exp_close -i $spid
'''.format(vnf_mgmt_ip=vnf_mgmt_ip, dns_mgmt_ip=dns_mgmt_ip, dns_sig_ip=dns_sig_ip, etcd_ip=etcd_ip))

    os.chmod(sh_file, stat.S_IRWXU)
    cmd = "{sh_file} {shared_config_exists}".format(sh_file=sh_file, shared_config_exists=shared_config_exists)
    logger.debug("Executing shell cmd : %s", cmd)
    rc = subprocess.call(cmd, shell=True)
    if rc != 0:
        raise ConfigurationError("Configuration of {} failed: {}".format(vnf_mgmt_ip, rc))

'''
   script to configure users on Homestead1
'''
def configure_users(logger, run_dir, vnf_mgmt_ip):
    time_to_wait = 6
    logger.debug("Sleeping for %s min while we wait for VNFs to stabilize ..", str(time_to_wait))
    for x in reversed(range(1,time_to_wait+1)):
       if x != time_to_wait:
           logger.debug("Sleeping for %d more min ..", x)
       time.sleep(60)

    sh_file = "{}/configure_hs-{}.sh".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
    logger.debug("Creating homestead script file to update users %s", sh_file)
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

# Add user 1001 with password Test123 to SIP domain test.com
send "/usr/share/clearwater/bin/create_user 1001 test.com Test123 --ifc /tmp/iFCs.xml\r"
expect "~$ "

# Add user 1002 with password Test123 to SIP domain test.com
send "/usr/share/clearwater/bin/create_user 1002 test.com Test123 --ifc /tmp/iFCs.xml\r"
expect "~$ "

exp_close -i $spid
'''.format(vnf_mgmt_ip=vnf_mgmt_ip))

    os.chmod(sh_file, stat.S_IRWXU)
    cmd = "{sh_file}".format(sh_file=sh_file)
    logger.debug("Executing shell cmd : %s", cmd)
    rc = subprocess.call(cmd, shell=True)
    if rc != 0:
        raise ConfigurationError("Configuration of users failed: {}".format(vnf_mgmt_ip, rc))

'''
   script to configure sprout VNf
'''     
def configure_sprout(logger, run_dir, vnf_mgmt_ip, vm_mgmt_ip, dns_mgmt_ip, dns_sig_ip, etcd_ip):
    sh_file = "{}/configure_sprout-{}.sh".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
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


exp_close -i $spid
'''.format(vnf_mgmt_ip=vnf_mgmt_ip, vm_mgmt_ip=vm_mgmt_ip, dns_mgmt_ip=dns_mgmt_ip, dns_sig_ip=dns_sig_ip, etcd_ip=etcd_ip))

    os.chmod(sh_file, stat.S_IRWXU)
    cmd = "{sh_file}".format(sh_file=sh_file)
    logger.debug("Executing shell cmd : %s", cmd)
    rc = subprocess.call(cmd, shell=True)
    if rc != 0:
        raise ConfigurationError("Configuration of {} failed: {}".format(vnf_mgmt_ip, rc))


def configure_sipp(logger, run_dir, vnf_mgmt_ip, vm_mgmt_ip, dns_mgmt_ip, vnfr_name):
    logger.debug("Copying needed files for SIPP scenario ")
    vnffile = get_vnf_file(logger, 'data1.csv', 'ccore_testbed_nsd', 'ccore_testbed_nsd',
                                              'nsd')
    copy_file_ssh_sftp(logger, vnf_mgmt_ip, 'fedora', '/tmp/', 'data1.csv', vnffile)
    vnffile = get_vnf_file(logger, 'reg_auth_dereg.xml', 'ccore_testbed_nsd', 'ccore_testbed_nsd',
                                              'nsd')
    copy_file_ssh_sftp(logger, vnf_mgmt_ip, 'fedora', '/tmp/', 'reg_auth_dereg.xml', vnffile)
    logger.debug("Done copying needed files for SIPP scenario ")
 
    logger.debug("Installing SIPP ")
    try:
       sess = pxssh.pxssh(options={
                    "StrictHostKeyChecking": "no",
                    "UserKnownHostsFile": "/dev/null"})
       sess.login(vnf_mgmt_ip, "fedora", "fedora")
       sess.timeout = 60

       sess.sendline("cp /tmp/data1.csv data1.csv")   # run a command
       sess.prompt()
       sess.sendline("cp /tmp/reg_auth_dereg.xml reg_auth_dereg.xml")   # run a command
       sess.prompt()
       #5551239800;[authentication username=5551239800@rift.io password=mypass0]
       sess.sendline("sed -i \"s/5551239800/1001/g\" data1.csv")   # run a command
       sess.prompt()
       sess.sendline("sed -i \"s/rift.io/test.com/\" data1.csv")   # run a command
       sess.prompt()
       sess.sendline("sed -i \"s/password=mypass0/password=Test123/\" data1.csv")
       sess.prompt()
       logger.debug("Logged in 6")
       sess.set_unique_prompt()
       sess.sendline("sudo su")
       sess.prompt()
       sippname2 = vnfr_name.replace("_", "")
       cmd_str = "echo {sippname2}.test.com > /etc/hostname".format(sippname2=sippname2)
       logger.debug("Logged in 7 sippname %s", sippname2)
       sess.set_unique_prompt()
       sess.sendline(cmd_str)
       sess.prompt()
       sess.sendline("hostname -F /etc/hostname")
       sess.prompt()
       sess.sendline("yum install -y bind-utils")
       sess.prompt()
       logger.debug("Installed bind-utils, Sleeping for 5")
       time.sleep(5)
       # Point to local DNS server
       cmd_str = "echo 'nameserver {dns_mgmt_ip}' > /etc/resolv.conf".format(dns_mgmt_ip=dns_mgmt_ip)
       sess.sendline(cmd_str)
       sess.prompt()
       logger.debug("Logged in 11")
       sess.sendline("exit")
       sess.prompt()
      
       sess.logout()

    except Exception as e:
       logger.exception("Exception seen while installing sipp %s", str(e))
       raise

    logger.debug("SIPP expect script done ") 




def main(argv=sys.argv[1:]):
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("yaml_cfg_file", type=argparse.FileType('r'))
        parser.add_argument("--quiet", "-q", dest="verbose", action="store_false")
        args = parser.parse_args()

        run_dir = os.path.join(os.environ['RIFT_INSTALL'], "var/run/rift")
        if not os.path.exists(run_dir):
            os.makedirs(run_dir)
        log_file = "{}/ccore_testbed_config-{}.log".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
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

        # Check if this is post scale out trigger
        def find_vnfr(vnfr_dict, mbr_vnf_index):
            try:
               return vnfr_dict[mbr_vnf_index]
            except KeyError:
               logger.warn("Could not find vnfr for mbr vnf index : %d", mbr_vnf_index)

        def find_cp_ip(vnfr, cp_name):
            for cp in vnfr['connection_point']:
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
            return vnfr['mgmt_ip_address']

        def get_vnfr_name(vnfr):
            return vnfr['name']

        def find_vdur_mgmt_ip(vnfr):
            return vnfr['vdur'][0]['vm_management_ip']

        def find_param_value(param_list, input_param):
            for item in param_list:
               logger.debug("Parameter: %s", format(item))
               if item['name'] == input_param:
                  return item['value']

        hs_list = []

        for mbr_index in range(1,4):
            hs_info = dict()
            hs_vnfr = find_vnfr(yaml_cfg['vnfr'], mbr_index)
            hs_vnf_name = get_vnfr_name(hs_vnfr)
            hs_info['mgmt_name'] = hs_vnf_name + "-mgmt"
            hs_info['floating_mgmt_ip'] = find_vnfr_mgmt_ip(hs_vnfr)
            hs_info['local_mgmt_ip'] = find_vdur_mgmt_ip(hs_vnfr)
            hs_info['sig_name'] = hs_vnf_name
            hs_info['sig_ip'] = find_cp_ip(hs_vnfr, 'homesteadprov_vnfd/sigport')
            hs_list.append(hs_info)

        dns_vnfr = find_vnfr(yaml_cfg['vnfr'], 5)
        dns_vnf_mgmt_ip = find_vnfr_mgmt_ip(dns_vnfr)
        dns_vnf_name = get_vnfr_name(dns_vnfr)
        dns_vm_mgmt_ip = find_vdur_mgmt_ip(dns_vnfr)
        dns_sig_ip = find_cp_ip(dns_vnfr, 'dnsserver_vnfd/sigport')

        sprout_info = dict()
        sprout_vnfr = find_vnfr(yaml_cfg['vnfr'], 6)
        sprout_vnf_name = get_vnfr_name(sprout_vnfr)
        sprout_info['mgmt_name'] = sprout_vnf_name + "-mgmt"
        sprout_info['floating_mgmt_ip'] = find_vnfr_mgmt_ip(sprout_vnfr)
        sprout_info['local_mgmt_ip'] = find_vdur_mgmt_ip(sprout_vnfr)
        sprout_info['sig_name'] = sprout_vnf_name
        sprout_info['sig_ip'] = find_cp_ip(sprout_vnfr, 'sprout_vnfd/sigport')

        sipp_info = dict()
        sipp_vnfr = find_vnfr(yaml_cfg['vnfr'], 4)
        sipp_vnf_name = get_vnfr_name(sipp_vnfr)
        sipp_info['mgmt_name'] = sipp_vnf_name + "-mgmt"
        sipp_info['floating_mgmt_ip'] = find_vnfr_mgmt_ip(sipp_vnfr)
        sipp_info['local_mgmt_ip'] = find_vdur_mgmt_ip(sipp_vnfr)

        etcd_ip = None
        etcd_ip = None
        for  hs_info in hs_list:
            logger.debug("Configuring DNS server VNF for %s..", hs_info['sig_name'])
            configure_dnsserver_hsentries(logger, run_dir, dns_vnf_mgmt_ip, dns_vm_mgmt_ip, hs_info)
        logger.debug("Configuring DNS server VNF for sprout.")
        configure_dnsserver_sproutentries(logger, run_dir, dns_vnf_mgmt_ip, dns_vm_mgmt_ip, sprout_info)

        for  hs_info in hs_list:
            logger.debug("Configuring Homestead VNF for %s..", hs_info['sig_name'])
            if etcd_ip is None:
                etcd_ip = hs_info['local_mgmt_ip']
                hs1_ip = hs_info['floating_mgmt_ip']
                configure_hs(logger, run_dir, hs_info['floating_mgmt_ip'], dns_vm_mgmt_ip, dns_sig_ip, etcd_ip)
            else:
                configure_hs(logger, run_dir, hs_info['floating_mgmt_ip'], dns_vm_mgmt_ip, dns_sig_ip, etcd_ip, shared_config_exists=True)

        logger.debug("Configuring Sprout VNF..")
        configure_sprout(logger, run_dir, sprout_info['floating_mgmt_ip'], sprout_info['local_mgmt_ip'], dns_vm_mgmt_ip, dns_sig_ip, etcd_ip)

        logger.debug("Adding users for one Homestead..")
        configure_users(logger, run_dir, hs1_ip)
        logger.debug("Configuring SIPP VNF..")
        configure_sipp(logger, run_dir, sipp_info['floating_mgmt_ip'], sipp_info['local_mgmt_ip'], dns_vm_mgmt_ip, sipp_vnf_name)
        logger.debug("Finished ccore testbed initial config")

    except Exception as e:
        logger.exception(e)
        raise

if __name__ == "__main__":
    main()
