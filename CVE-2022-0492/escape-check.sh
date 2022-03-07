#!/bin/bash

echo "[*] Testing if CVE-2022-0492 can be exploited for container escape" 

# test dir
test_dir=/tmp/.cve-2022-0492-test
if ! mkdir -p $test_dir ; then
    echo "[-] ERROR: failed to create test directory at $test_dir" 
    exit 1
fi

# Testing escape via CAP_SYS_ADMIN is possible - v1
if mount -t cgroup -o memory cgroup $test_dir >/dev/null 2>&1 ; then
    if test -w $test_dir/release_agent ; then
        echo "[!] Exploitable: the container can escape as it runs with CAP_SYS_ADMIN"
        umount $test_dir && rm -rf $test_dir
        exit 0
    fi
    umount $test_dir
fi

# Testing escape via user namespaces is possible - v2
while read -r subsys
do
    if unshare -UrmC --propagation=unchanged bash -c "mount -t cgroup -o $subsys cgroup $test_dir 2>&1 >/dev/null && test -w $test_dir/release_agent" >/dev/null 2>&1 ; then
        echo "[!] Exploitable: the container can abuse user namespaces to escape"
        rm -rf $test_dir
        exit 0
    fi
done <<< $(cat /proc/$$/cgroup | grep -Eo '[0-9]+:[^:]+' | grep -Eo '[^:]+$')

# Cannot escape via either method
rm -rf $test_dir
echo "[-] ERROR: cannot escape via CVE-2022-0492"
