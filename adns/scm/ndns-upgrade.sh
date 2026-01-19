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

    # set nic ADNS
    nics_pci=""
    if [[ $1 == "MLX" ]];then
        t1_pci=`ethtool -i t1 |grep bus-info | awk -F' ' '{print $2}'`
        if [[ $t1_pci ]] ; then
            echo "t1_pci is "  $t1_pci
        else
            err_exit "get bus-info of t1 error, t1_pci is null"
        fi

        t2_pci=`ethtool -i t2 |grep bus-info | awk -F' ' '{print $2}'`
        if [[ $t2_pci ]] ; then
            echo "t2_pci is "  $t2_pci
        else
            err_exit "get bus-info of t2 error, t2_pci is null"
        fi
        nics_pci=" -w "$t1_pci" -w "$t2_pci 
		echo $nics_pci
		echo $nics_pci
		echo $nics_pci
        /home/adns/bin/adns -c $core_mask -n 3 $nics_pci --proc-type=primary --base-virtaddr=0x4300000000  -- -p 0x3 -f /home/adns/etc/adns.conf &>/tmp/adns-launch.log
    else
        /home/adns/bin/adns -c $core_mask -n 3 --proc-type=primary --base-virtaddr=0x4300000000  -- -p 0x3 -f /home/adns/etc/adns.conf &>/tmp/adns-launch.log
    fi


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
	if [[ $2 == "cloud" ]]; then
		echo "vEth0 and vEth1 are up"
	else
		ifup vEth0 && ifup vEth1 || err_exit "fail to ifup vEth0 or vEth1"
	fi
}

function install_configs()
{
    _type=$1
    _mem=$2
    _nic=$3
    _env=$4
    _ipv6=$5

    config_model="hiadns-${_type}-${_mem}g-ndns"
    if [[ $_nic == "40G" ]];then
        if [[ $5 == true ]];then
            conf_name="adns_${_nic}_v6"  
        else
            conf_name="adns_${_nic}"
        fi
    else
        if [[ $5 == true ]];then
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
    upgrade.sh -m memory -n NIC_type [-D] [-e GAOFANG] [-P] [-6]
    -t    adns type, a | v, a for hichina-a, v for hichina-v
    -n    NIC type, 10G | 40G | MLX
    -D    init DPDK environment
    -e    adns environment, GAOFANG | CLOUD
    -P    PVT_ZONE version
    -6    IPV6

EXAMPLE
    sudo sh upgrade.sh -t a -n 10G -D"

if [ $# -lt 5 ]; then
    err_exit "$USAGE"
fi

PVT_ZONE=false
IPV6=false
ADNS_ENV="corp"
while getopts "v:t:n:De:P6" arg
do
    case $arg in
        t)
            TYPE=${OPTARG}
            if [[ $TYPE != "a" && $TYPE != "v" ]]; then
                err_exit "Invalid adns type. $USAGE"
            fi
            ;;
        n)
            NIC_TYPE=${OPTARG}
            if [[ $NIC_TYPE != "10G" && $NIC_TYPE != "40G" && $NIC_TYPE != "MLX" ]]; then
                err_exit "Invalid NIC type. $USAGE"
            fi
            ;;
        D)
            DPDKENV_INIT=true
            ;;
        e)
            ADNS_ENV=${OPTARG,,} # ,, means to lower magically
            if [[ $ADNS_ENV != "gaofang" && $ADNS_ENV != "cloud" ]]; then
                err_exit "Invalid ADNS ENV type. $USGAE"
            fi
            ;;
        P)
            PVT_ZONE=true
            ;;
        6)
            IPV6=true
            ;;
        ?)
            err_exit "$USAGE"
            ;;
    esac
done

AGENT_PATH="hichina-adns-agent"
MEM=$(get_mem)
install_configs $TYPE $MEM $NIC_TYPE $ADNS_ENV $IPV6
set_offline $AGENT_PATH $ADNS_ENV $IPV6
/home/ndns/sbin/nginx -s stop
shutdown_adns
[[ $DPDKENV_INIT ]] && init_dpdkenv $NIC_TYPE
lauch_adns $NIC_TYPE $ADNS_ENV

