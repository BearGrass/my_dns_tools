
#!/bin/bash


linux_release_path=/etc/issue
numa_path=/proc/buddyinfo
rx="rx=(0,1,2),(0,2,3),(0,3,4),(0,4,5),(0,5,6),(0,6,7),(0,7,8),(0,8,9),(1,1,2),(1,2,3),(1,3,4),(1,4,5),(1,5,6),(1,6,7),(1,7,8),(1,8,9)"
tx="tx=(0,1,2),(0,2,3),(0,3,4),(0,4,5),(0,5,6),(0,6,7),(0,7,8),(0,8,9),(1,1,2),(1,2,3),(1,3,4),(1,4,5),(1,5,6),(1,6,7),(1,7,8),(1,8,9)"

REQUIRE_KERNEL_VERSION="2.6.32-220.23.2.ali878.el6.x86_64"
REQUIRE_LINUX_RELEASE="Red Hat Enterprise Linux Server release 6.2 (Santiago)"
mem_max_size=180
mem_min_size=10

function check_kernel_version()
{
    kernel_version=`uname -r`
#    echo $kernel_version
    if [ "$kernel_version" = "$REQUIRE_KERNEL_VERSION" ]; then
        return 1
    fi
    return 0
}


function check_linux_release()
{
    linux_release=`sed -n '1p' $linux_release_path`
#    echo $linux_release
    if [ "$linux_release" = "$REQUIRE_LINUX_RELEASE" ]; then
        return 1
    fi
    return 0
}

function check_numa()
{
    node_num=`lscpu | grep "NUMA node(s)" | awk '{print $3}'`
    if [ $node_num -eq 1 ]; then
        return 1
    fi
    return 0
}

function check_hyper_thread()
{
    node_num=`lscpu | grep "Thread(s) per core:" | awk '{print $4}'`
    if [ $node_num -eq 1 ]; then
        return 1
    fi
    return 0
}

function check_free_memory_size_before_dpdk_start()
{
    free_mem=$(free -g |grep - |awk -F : '{print $2}' |awk '{print $2}')
#    echo $free_mem
    if [ $free_mem -lt $mem_max_size ]; then
        return 0
    fi
    return 1
}

function check_free_memory_size_after_dpdk_start()
{
    free_mem=$(free -g |grep - |awk -F : '{print $2}' |awk '{print $2}')
#    echo $free_mem
    if [ $free_mem -lt $men_min_size ]; then
        return 0
    fi
    return 1
}

function check_adns_conf_file_core_number()
{
    free_mem=$(free -g |grep - |awk -F : '{print $2}' |awk '{print $2}')
    conf_rx=`cat /home/adns/etc/adns.conf | grep "^rx"`
    conf_tx=`cat /home/adns/etc/adns.conf | grep "^tx"`
#    echo $free_mem
    if [[ "$conf_rx" = "$rx" && "$conf_tx" = "$tx" ]]; then
        return 1
    fi
    return 0
}

function check_adns_start_parameter_core_number()
{
    node_num=`ps aux | grep adns | grep "0x3ff" | wc -l`
    if [ $node_num -eq 1 ]; then
        return 1
    fi
    return 0

}

check_kernel_version
ret=$?
if [ $ret == 1 ];then
    echo -e "check kernel version [\e[1;32mpass\e[0m], kernel version is $REQUIRE_KERNEL_VERSION..."
else
    echo -e "check kernel version [\e[1;31mfailed\e[0m],please change kernel version to $REQUIRE_KERNEL_VERSION"
fi

check_linux_release
ret=$?
if [ $ret == 1 ]; then
    echo -e "check linux release [\e[1;32mpass\e[0m], linux release is $REQUIRE_LINUX_RELEASE..."
else
    echo -e "check linux release [\e[1;31mfailed\e[0m],please change linux release to $REQUIRE_LINUX_RELEASE"
fi 

check_numa
ret=$?
if [ $ret == 1 ]; then
    echo -e "check numa [\e[1;32mpass\e[0m], numa is open..."
else
    echo -e "check numa [\e[1;31mfailed\e[0m],please open the numa..."
fi 


check_hyper_thread
ret=$?
if [ $ret == 1 ]; then
    echo -e "check hyper-threading [\e[1;32mpass\e[0m],hyper-threading is off..."
else
    echo -e "check hyper-threading [\e[1;31mfailed\e[0m],please turn off the hyper-threading..."
fi 


case "$1" in
    machine)
        check_free_memory_size_before_dpdk_start
        ret=$?
        if [ $ret == 0 ];then
            echo -e "check free memory [\e[1;31mfailed\e[0m], free memory size less than $mem_max_size G..."
        else
        {
            free_mem=$(free -g |grep - |awk -F : '{print $2}' |awk '{print $2}')
            echo -e "check free memory [\e[1;32mpass\e[0m], free memory is $free_mem G..."
        }
        fi

        exit 0
        $1
        ;;
    config)
        check_free_memory_size_after_dpdk_start
        ret=$?
        if [ $ret == 0 ];then
            echo -e "check free memory [\e[1;31mfailed\e[0m], free memory size less than $mem_min_size G..."
        else
        {
            free_mem=$(free -g |grep - |awk -F : '{print $2}' |awk '{print $2}')
            echo -e "check free memory [\e[1;32mpass\e[0m], free memory is $free_mem G..."
        }
        fi

        check_adns_conf_file_core_number
        ret=$?
        if [ $ret == 0 ];then
            echo -e "check config file core number[\e[1;31mfailed\e[0m], core not 10 core..."
        else
        {
            echo -e "check config file core number[\e[1;32mpass\e[0m], core 10 core..."
        }
        fi

        exit 0
        $1        
        ;;
    adns)
        check_free_memory_size_after_dpdk_start
        ret=$?
        if [ $ret == 0 ];then
            echo -e "check free memory [\e[1;31mfailed\e[0m], free memory size less than $mem_min_size G..."
        else
        {
            free_mem=$(free -g |grep - |awk -F : '{print $2}' |awk '{print $2}')
            t=1024
            free_mem=`echo "scale=0;$free_mem/$t"|bc`
            echo -e "check free memory [\e[1;32mpass\e[0m], free memory is $free_mem G..."
        }
        fi

        check_adns_conf_file_core_number
        ret=$?
        if [ $ret == 0 ];then
            echo -e "check config file core number[\e[1;31mfailed\e[0m], core not 10 core..."
        else
        {
            echo -e "check config file core number[\e[1;32mpass\e[0m], core 10 core..."
        }
        fi

        check_adns_start_parameter_core_number
        ret=$?
        if [ $ret == 0 ];then
            echo -e "check adns start parameter core number[\e[1;31mfailed\e[0m], core is not --c 0x3ff parameter..."
        else
        {
            echo -e "check adns start parameter core number[\e[1;32mpass\e[0m], core is --c 0x3ff parameter..."
        }
        fi

        exit 0
        $1        
        ;;

    *)
        echo $""
        echo $"Usage: $0 {machine | config | adns}"
        echo $"machine : before dpdk start"
        echo $"config  : before adns start"
        echo $"adns    : after adns start"
        echo $"$0"
        exit 2
        $1        
        ;;


esac
exit $?

