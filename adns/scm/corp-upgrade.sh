#!/bin/bash

source ./ndns-libupgrade.sh

function lauch_adns()
{
    if ps aux | grep zone_init | grep -qv "grep"; then
        echo "Agent fetching or loading is already started."
        exit 1
    fi

    # launch ADNS
    if [[ $1 == "40G" ]];then
        core_mask="0xfffff"
    else
        core_mask="0x3fff"
    fi

    /home/adns/bin/adns -c $core_mask -n 3  --proc-type=primary --base-virtaddr=0x4300000000  -- -p 0x3 -f /home/adns/etc/adns.conf &>/tmp/adns-launch.log

    if [[ $2 == "cloud" ]]; then
        echo "ADNS is launching"
        while true; do
            if /home/adns/bin/adns_adm -s &>/dev/null; then
                break
            else
                sleep 1
                echo -n "."
            fi
        done
        echo ""
        echo "ADNS launching is done"
        ifup vEth0 && ifup vEth1 || err_exit "fail to ifup vEth0 or vEth1"

        echo "Connecting neighbor."
        while true; do
            n=`ip r | grep -e "nexthop.*vEth0\|nexthop.*vEth1" | wc -l`
            if [[ $n == 2 ]]; then
                break
            else
                sleep 1
                echo -n "."
            fi
        done
        echo ""
    fi

    if [[ $PB_AGENT == false ]]; then 
        curl --connect-timeout 600 http://127.0.0.1:8888/load_zone_data || exit 1
        ifup vEth0 && ifup vEth1 || exit 1
        return;
    fi

    # start fetching
    echo "Start fetching."
    sudo -u admin /home/admin/${AGENT_PATH}/virtualenv/bin/python /home/admin/${AGENT_PATH}/target/${AGENT_PATH}/service/zone_init.py file &>/tmp/adns-fetch.log &

    # detect fetching is completed or not
    while true; do
            if /home/adns/bin/adns_adm -s &>/dev/null; then
                    if ps aux | grep zone_init | grep -qv "grep"; then
                            sleep 1
                            echo -n "*"
                    else
                            echo ""
                            echo "Fetching is done."
                            break
                    fi
        else
            sleep 1
            echo -n "."
            fi
    done

    # start loading
    echo "Start loading."
    sudo -u admin /home/admin/${AGENT_PATH}/virtualenv/bin/python /home/admin/${AGENT_PATH}/target/${AGENT_PATH}/service/zone_init.py adns &>/tmp/adns-load.log
    echo "Loading is done."
    ifup vEth0 && ifup vEth1 || err_exit "fail to ifup vEth0 or vEth1"
}

function install_configs()
{
    _nic=$1
    _env=$2
    _ipv6=$3

    config_model="corp"
    if [[ $_nic == "40G" ]];then
        if [[ $_ipv6 == true ]];then
            conf_name="adns_${_nic}_v6"
        else
            conf_name="adns_${_nic}"
        fi
    else
        if [[ $_ipv6 == true ]];then
            conf_name="adns_v6"
        else
            conf_name="adns"
        fi
    fi
    if [[ $_env == "cloud" ]];then
        conf_name="${conf_name}_cloud"
    fi
    conf_name="${conf_name}.conf"
    cp ./$config_model/$conf_name /home/adns/etc/adns.conf || err_exit "fail to copy configs into /home/adns/etc"
    find ./$config_model/ ! -name 'adns*.conf' -type f -exec cp {} /home/adns/etc/ \; || err_exit "fail to copy configs into /home/adns/etc"
}



USAGE="
USAGE
    upgrade.sh -m memory -v version -n NIC_type [-D] [-Q]
    -v    adns version number, like 2.14.5
    -n    support NIC type, 10G | 40G
    -D    init DPDK environment
    -e    adns environment, GAOFANG | CLOUD
    -p    adns-agent-pb
    -6    IPV6

EXAMPLE
    sudo sh upgrade.sh -v 2.14.5 -n 10G -D"

if [ $# -lt 2 ]; then
    err_exit "$USAGE"
fi

IPV6=false
ADNS_ENV="corp"
PB_AGENT=false

while getopts "pn:De:6" arg
do
    case $arg in
        D)
            DPDKENV_INIT=true
            ;;
        p)
            PB_AGENT=true
            ;;
        n)
            NIC_TYPE=${OPTARG}
            if [[ $NIC_TYPE != "10G" && $NIC_TYPE != "40G" ]]; then
                err_exit "Invalid NIC type. $USAGE"
            fi
            ;;
        e)
            ADNS_ENV=${OPTARG,,} # ,, means to lower magically
            if [[ $ADNS_ENV != "gaofang" && $ADNS_ENV != "cloud" ]]; then
                err_exit "Invalid ADNS ENV type. $USGAE"
            fi
            ;;
        6)
            IPV6=true
            ;;
        ?)
            err_exit "$USAGE"
            ;;
    esac
done

AGENT_PATH="corp-adns-agent"
install_configs $NIC_TYPE $ADNS_ENV $IPV6
set_offline $AGENT_PATH $ADNS_ENV $IPV6
shutdown_adns
sleep 5
[ $DPDKENV_INIT ] && init_dpdkenv
lauch_adns $NIC_TYPE $ADNS_ENV
