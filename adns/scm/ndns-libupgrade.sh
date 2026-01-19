#!/bin/bash

##
# helpers
##
function err_exit()
{
    echo "Error: $1"
    exit 1
}

##
# procedures
##
function get_mem()
{
    if [ `free -g | grep Mem | awk '{print $2}'` -gt 185 ]; then
        mem=190
    else
        mem=95
    fi
    echo $mem
}

# this is obseleted
function get_scm()
{
    rm -rf ./adns-scm
    git clone http://gitlab-sc.alibaba-inc.com/alibaba-dns/adns-scm.git --depth 1 &> /dev/null || err_exit "fail to fetch adns_scm"
}

function set_alarmoff()
{
    rpm -q ali-monitor-api &> /dev/null || yum install ali-monitor-api -b test -y &> /dev/null
    rpm -q ali-monitor-api || err_exit "no alimonitor api and installation failed"
    alimonitor_api notice -scopeType 1 -scope `hostname` -act 0 -message "upgrading" -afterTime 60 -user alidns -key 6fad273d67667974d0c4956721fd9802  #todo: check ret string
}

function set_offline()
{
    agent_path=$1
    env=$2
    ipv6=$3

    sudo pkill ospfd
    if [[ $env == "cloud" ]];then
        if [[ $ipv6 == true ]];then
            sudo /home/tops/bin/tops-bgpops del_all_net_v6 || err_exit "fail to delete service IP"
        else
            sudo /home/tops/bin/tops-bgpops del_all_net || err_exit "fail to delete service IP"
        fi
    else
        sudo pkill bgpd
    fi

    echo ""
    echo "Shutting down ADNS traffic"
    while false; do
        qps=`/home/adns/bin/adns_adm --stats | grep qps | awk '{print $2}'`
        if [[ $qps == '0' ]]; then
            echo ""
            echo "ADNS traffic is down"
            break
        else
            sleep 1
            echo -n "#"
        fi
    done

    sudo -u admin /home/admin/${agent_path}/virtualenv/bin/python /home/admin/${agent_path}/target/${agent_path}/service/zone_init.py --force offline || err_exit "fail to set offline" 
}

function shutdown_adns()
{
    pkill -f "/home/adns/bin/adns"
}

function init_dpdkenv()
{
    modprobe i2c_core
    if [[ $1 == "MLX" ]];then
    	/home/adns/scripts/deploy.sh reinitmlx t1 t2|| exit 1
    else
    	/home/adns/scripts/deploy.sh reinit t1 t2 || exit 1
    fi
}

function upgrade_adns()
{
    if [[ $2 == "40G" ]];then
        version="$1_$2"
    else
        version=$1
    fi
    if [[ $3 == true ]];then
        version=$version"_PVTZ"
    fi
    if [[ $4 == true ]];then
        version=$version"_IPV6"
    fi
    
    kernel_version=`cat /etc/redhat-release|cut -d " " -f 7|cut -d "." -f 1`
    [[ $kernel_version = 7 ]] && kernel="alios7"
    [[ $kernel_version = 6 ]] && kernel="alios6" 

    rpm_name="adns-core-$version-1.$kernel.x86_64.rpm"
    [ -f ./release-rpms/$rpm_name ] || err_exit "fail to find $rpm_name in release-rpms"
    rpm -Uvh ./release-rpms/$rpm_name &> /dev/null
    rpm -qa | grep -q "adns-core-$version" || err_exit "rpm installation failed"
}
