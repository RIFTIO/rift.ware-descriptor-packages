#!/usr/bin/env python3
import argparse
import logging
import os
import stat
import subprocess
import sys
import time
import yaml


class ConfigurationError(Exception):
    pass


def configure_http_client(logger, run_dir, mgmt_ip, haproxy_cp_ip):
    sh_file = "{}/http_client_config-{}.sh".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
    logger.debug("Creating script file %s", sh_file)
    with open(sh_file, "w") as f:
        f.write(r'''#!/usr/bin/expect -f
set login "centos"
set addr {mgmt_ip}
set pw "centos"

set retry 0
set max 20
while {{ $retry < $max }} {{
    sleep 5
    spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $login@$addr

    set timeout 10

    expect "yes/no" {{
          send "yes\r"
          expect "*?assword:" {{ send "$pw\r"; break }}
          }} "*?assword:" {{ send "$pw\r"; break }}

    set retry [ expr $retry+1 ]

    if {{ $retry == $max }} {{
        puts "Configuration timed out."
        exit 1
    }}
}}

expect "]$ "
send "sudo su\r"
expect "]# "

# Move the default index.html so we get served the noindex page which
# has more content.
send "curl -H \"Content-Type: application/json\" -X POST -d '{{\"url\":\"http://{haproxy_cp_ip}/\"}}' http://{mgmt_ip}:18888/api/server\r"
expect "]# "
'''.format(haproxy_cp_ip=haproxy_cp_ip, mgmt_ip=mgmt_ip))

    os.chmod(sh_file, stat.S_IRWXU)
    rc = subprocess.call(sh_file, shell=True)
    if rc != 0:
        raise ConfigurationError("HAProxy add http client config failed: {}".format(rc))

def main(argv=sys.argv[1:]):
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("yaml_cfg_file", type=argparse.FileType('r'))
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--quiet", "-q", dest="verbose", action="store_false")
        args = parser.parse_args()

        run_dir = os.path.join(os.environ['RIFT_INSTALL'], "var/run/rift")
        if not os.path.exists(run_dir):
            os.makedirs(run_dir)
        log_file = "{}/rift_http_client_config-{}.log".format(run_dir, time.strftime("%Y%m%d%H%M%S"))
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
        def find_cp_ip(vnfr_list, vnfd_name, cp_name):
            for vnfr in vnfr_list:
                if vnfd_name in vnfr['name']:
                    for cp in vnfr['connection_points']:
                        logger.debug("Connection point: %s", format(cp))
                        if cp_name in cp['name']:
                            return cp['ip_address']

            raise ValueError("Could not find vnfd %s connection point %s", vnfd_name, cp_name)

        def find_mgmt_ip(vnfr_list, vnfd_name):
            for vnfr in vnfr_list:
                if vnfd_name in vnfr['name']:
                    return vnfr['rw_mgmt_ip']

            raise ValueError("Could not find vnfd %s mgmt ip", vnfd_name)

        def find_vnfr(vnfr_list, vnfd_name):
            for vnfr in vnfr_list:
                if vnfd_name in vnfr['name']:
                    return vnfr

            raise ValueError("Could not find vnfd %s", vnfd_name)

        haproxy_cp_ip = find_cp_ip(yaml_cfg['vnfrs_others'], "haproxy_vnfd", "cp2")
        http_client_mgmt_ip = find_mgmt_ip(yaml_cfg['vnfrs_in_group'], "http_client_vnfd")

        if yaml_cfg['trigger'] == 'post_scale_out':
            logger.debug("Sleeping for 60 seconds to give VNFD mgmt VM a change to boot up")
            time.sleep(60)

            configure_http_client(logger, run_dir, http_client_mgmt_ip, haproxy_cp_ip)
            logger.debug("End of HTTP client config")
        elif yaml_cfg['trigger'] == 'pre_scale_in':
            pass
        else:
            raise ValueError("Unexpected trigger {}".format(yaml_cfg['trigger']))


    except Exception as e:
        logger.exception(e)
        raise

if __name__ == "__main__":
    main()
