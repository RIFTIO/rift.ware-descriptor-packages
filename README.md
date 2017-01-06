
   Copyright 2017 RIFT.IO Inc

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.


Generates the NSD and VNFD descriptor packages from source

To generate the packages type "make". The VNF and NSD packages will be located
build/vnfd_pkgs and build/nsd_pkgs.

To clean, type 'make clean'.

You need to install charm tools to compile the charms required for the packages.
On Fedora, install using: pip install charm-tools
On Ubuntu, install using: apt install charm-tools
For other platforms, check https://jujucharms.com/docs/2.0/tools-charm-tools


