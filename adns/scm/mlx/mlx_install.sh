#!/bin/bash
git clone git@gitlab.alibaba-inc.com:alibaba-dns/mlx_sdk.git
tar xvf MLNX_OFED_LINUX-3.4-1.0.0.0-rhel7.2-x86_64.tgz

cd MLNX_OFED_LINUX-3.4-1.0.0.0-rhel7.2-x86_64
./mlnxofedinstall --add-kernel-support --skip-repo --without-fw-update --without-mlnx-nvme --distro rhel7.2 --force
