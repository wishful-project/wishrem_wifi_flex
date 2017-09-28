UniFlex WiFI Flex Module
============================

Download from GitHub
====================================

	sudo apt-get install git
	git clone https://github.com/wishful-project/wishrem_wifi_flex
	cd wishrem_wifi_flex/

Requirements installation
============

	sudo xargs apt-get install -y < requirements.system

Installation
============

	pip3 install -r requirements.txt --upgrade
	sudo python3 setup.py install

Running examples
================

1. Local node:


	cd node_app/

Change IP address of sub and pub to be the IP address of the broker (in yaml files)

	sudo uniflex-agent --config ./config_slave_1.yaml


Alternative (TWIST testbed) install
================

Use ansible and documentation on repo:
	git clone https://github.com/wishful-project/wishrem_nodes_ansible

## Acknowledgement
The research leading to these results has received funding from the European
Horizon 2020 Programme under grant agreement n645274 (WiSHFUL project).
