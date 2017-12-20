#
#   Copyright 2017 RIFT.IO Inc
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
#
BUILD_DIR = build

NSDS := ping_pong_ns ping_pong_scale_ns
NSD_SRC_DIR := src/nsd
NSD_BUILD_DIR := $(BUILD_DIR)/nsd

NSD_SRC_DIRS := $(addprefix $(NSD_SRC_DIR)/, $(NSDS))
NSD_BUILD_DIRS := $(addprefix $(NSD_BUILD_DIR)/, $(NSDS))
NSD_PKGS := $(addsuffix .tar.gz, $(NSDS))
NSD_BUILD_PKGS := $(addprefix $(NSD_BUILD_DIR)_pkgs/, $(NSD_PKGS))

VNFDS := ping_vnf pong_vnf ping_scale_vnf pong_scale_vnf
VNFD_SRC_DIR := src/vnfd
VNFD_BUILD_DIR := $(BUILD_DIR)/vnfd

VNFD_SRC_DIRS := $(addprefix $(VNFD_SRC_DIR)/, $(VNFDS))
VNFD_BUILD_DIRS := $(addprefix $(VNFD_BUILD_DIR)/, $(VNFDS))
VNFD_PKGS := $(addsuffix .tar.gz, $(VNFDS))
VNFD_BUILD_PKGS := $(addprefix $(VNFD_BUILD_DIR)_pkgs/, $(VNFD_PKGS))

CHARM_REPO="https://osm.etsi.org/gerrit/osm/juju-charms.git"

all: $(VNFD_BUILD_PKGS) ${NSD_BUILD_PKGS}
	echo $@

clean:
	-@ $(RM) -rf $(BUILD_DIR)

$(VNFD_BUILD_DIR)/%: $(VNFD_SRC_DIR)/%
	mkdir -p $(VNFD_BUILD_DIR)
	cp -rf $< $(VNFD_BUILD_DIR)

	src/gen_vnfd_pkg.sh $< $@

$(BUILD_DIR)/juju-charms:
	mkdir -p $(BUILD_DIR)
	-cd $(BUILD_DIR) && (test -e juju-charms || git clone $(CHARM_REPO))
	-cd $(BUILD_DIR)/juju-charms && make

$(NSD_BUILD_DIR)/%: $(NSD_SRC_DIR)/%
	mkdir -p $(NSD_BUILD_DIR)
	cp -rf $< $(NSD_BUILD_DIR)

	src/gen_nsd_pkg.sh $< $@

$(BUILD_DIR)/nsd_pkgs/%.tar.gz: $(NSD_BUILD_DIR)/%
	src/generate_descriptor_pkg.sh -d $(BUILD_DIR)/nsd_pkgs $<
	rm -rf $(NSD_BUILD_DIR)

$(BUILD_DIR)/vnfd_pkgs/%.tar.gz: $(VNFD_BUILD_DIR)/%
	src/generate_descriptor_pkg.sh -d $(BUILD_DIR)/vnfd_pkgs $<
	rm -rf $(VNFD_BUILD_DIR)
