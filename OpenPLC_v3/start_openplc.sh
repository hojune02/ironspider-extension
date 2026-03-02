#!/bin/bash
if [ -d "/docker_persistent" ]; then
    mkdir -p /docker_persistent/st_files
    cp -n /workdir/webserver/dnp3_default.cfg /docker_persistent/dnp3.cfg
    cp -n /workdir/webserver/openplc_default.db /docker_persistent/openplc.db
    cp -n /workdir/webserver/active_program_default /docker_persistent/active_program
    cp -n /workdir/webserver/st_files_default/* /docker_persistent/st_files/
    cp -n /dev/null /docker_persistent/persistent.file
    cp -n /dev/null /docker_persistent/mbconfig.cfg
fi
cd "/home/hojune/github_projects/ironspider-extension/OpenPLC_v3/webserver"
"/home/hojune/github_projects/ironspider-extension/OpenPLC_v3/.openplc/bin/python3" webserver.py
