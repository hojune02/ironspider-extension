#!/bin/bash
cd /home/hojune/github_projects/ironspider-extension/OpenPLC_v3/webserver
source ../.openplc/bin/activate
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
sudo -E $(which python) webserver.py