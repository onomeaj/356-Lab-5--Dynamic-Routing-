#!/bin/bash
mkdir pcap_files
chmod 777 pcap_files

cd pox_module
sudo python2 setup.py develop

pkill -9 sr_solution
pkill -9 sr

