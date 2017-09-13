#!/usr/bin/env python3
import argparse
import logging
import os
import stat
import subprocess
import sys
import time
import yaml
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
vnfr_name: NS1__sprout_vnfd__6
'''
class ConfigurationError(Exception):
    pass

'''
   script to configure sprout VNf
'''     
def configure_sprout(logger, run_dir, vnf_mgmt_ip, vm_mgmt_ip, vnfr_name):
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

# Rename Host
set sproutname {vnfr_name}
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

exp_close -i $spid
'''.format(vnf_mgmt_ip=vnf_mgmt_ip, vm_mgmt_ip=vm_mgmt_ip, vnfr_name=vnfr_name))

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
        log_file = "{}/sprout_initial_config-{}.log".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
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

        def find_vnfr(vnfr_dict, name):
            try:
               for k, v in vnfr_dict.items():
                   if v['name'] == name:
                       return v
            except KeyError:
               logger.warn("Could not find vnfr for name : %s", name)

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

        sprout_vnfr = find_vnfr(yaml_cfg['vnfr'], yaml_cfg['vnfr_name'])
        sprout_vnf_mgmt_ip = find_vnfr_mgmt_ip(sprout_vnfr)
        sprout_vnf_name = get_vnfr_name(sprout_vnfr)
        sprout_vm_mgmt_ip = find_vdur_mgmt_ip(sprout_vnfr)
        logger.debug("Sleeping for 1 min while we wait for VNFs to boot up ..")
        time.sleep(60)
        logger.debug("Configuring Sprout VNF..")
        configure_sprout(logger, run_dir, sprout_vnf_mgmt_ip, sprout_vm_mgmt_ip, sprout_vnf_name)
        logger.debug("Done with configuring sprout VNF..")

    except Exception as e:
        logger.exception(e)
        raise

if __name__ == "__main__":
    main()
