#!/bin/sh
#****************************************************************#
# ScriptName: network_irq.sh
# Author: lei.xu@alibaba-inc.com
# Create Date: 2016-03-10 14:37
#***************************************************************#


get_cpu_array(){
    slave_id=$1
    phy_array=($(cat /proc/cpuinfo  |grep "^physical id"|awk '{print $NF}'))
    core_array=($(cat /proc/cpuinfo  |grep "^core id"|awk '{print $NF}'))
    m=$((${#phy_array[@]}-1))
    cpu_array=()
    if [[ $slave_id == "0" ]];then
        m_array=($(seq 1 $m))
        tmp_array=($(cat /proc/cpuinfo  |grep "^physical id"|awk '{print $NF}'|sort -un))
    else
        m_array=($(seq $m -1 1))
        tmp_array=($(cat /proc/cpuinfo  |grep "^physical id"|awk '{print $NF}'|sort -unr))
    fi
    for k in `seq 1 20`;do
        phy_id_array=(${phy_id_array[@]} ${tmp_array[@]})
    done
    k=1
    for i in ${m_array[@]};do
        id=${phy_id_array[$k]}
        for j in ${m_array[@]};do
            if [[ ${phy_array[$j]} == "$id" ]];then
                cpu_array=(${cpu_array[@]} $j)
                phy_array[$j]="T"
                k=$(($k+1))
                break
            fi
        done
    done

    for k in `seq 1 2`;do
        cpu_array=(${cpu_array[@]} ${cpu_array[@]})
    done
    echo ${cpu_array[@]}
}

get_irq_array(){
    nic=$1
    if [[ `cat /proc/interrupts|grep -i "${nic}-"|wc -l` == "0" ]];then
        irq_array=($(cat /proc/interrupts | grep -iw ${nic} |cut -d: -f1 | sed "s/ //g"))
    else
        irq_array=($(cat /proc/interrupts | grep -i "${nic}-"|cut -d: -f1 | sed "s/ //g"))
    fi
    echo ${irq_array[@]}
}

nic_irq_bind(){
    nic=$1
    nic_num=$2
    echo -ne "`date "+%F %T"` Info: set $nic IRQ smp_affinity:"
    irq_array=($(get_irq_array $nic))
    cpu_array=($(get_cpu_array $nic_num))
    for i in `seq 0 $((${#irq_array[*]}-1))`;do
        cpu_num=$(echo "obase=16;$((2 ** ${cpu_array[$i]}))"|bc)
        echo $cpu_num > /proc/irq/${irq_array[$i]}/smp_affinity
        echo -ne " "`cat /proc/irq/${irq_array[$i]}/smp_affinity_list`
    done
    echo
}


get_up_nic(){
    for dev in /sys/class/net/*/device
    do
        nic=$(echo $dev|cut -d'/' -f5)
        if [[ `echo $nic|grep -qE 'vif|tmp|usb'|wc -l` != "0" \
            || `ls -ld /sys/class/net/${nic}/device/driver/vif* 2>/dev/null|wc -l` != "0" \
            || `/sbin/ifconfig $nic 2>/dev/null |grep $nic|wc -l` == "0" \
            || `ls -ld /sys/class/net/${nic}/device/driver/virtio* 2>/dev/null|wc -l` != "0" \
            || `/sbin/ethtool -i ${nic} 2>/dev/null|grep driver|grep -E "ixgbevf|netxen_nic|bridge|veth|bonding|vif|virtio"|wc -l` != "0" \
            ]];then
            continue
        fi
        [[ $(cat /sys/class/net/${nic}/operstate) == "up" ]] && echo $nic
    done
}



do_set(){
    if ps -ef|grep -v grep |grep -q irqbalance;then
        service irqbalance stop >/dev/null
    fi
    mmm=0
    for nic in `get_up_nic`;do
        nic_irq_bind ${nic} $mmm
        if [[ $mmm == "0" ]];then
            mmm=1
        else
            mmm=0
        fi
    done
}

do_list(){
    for nic in `get_up_nic`;do
        echo -ne "$nic current IRQ smp_affinity:"
        for irq_nnn in `get_irq_array $nic`;do
            echo -ne " "`cat /proc/irq/${irq_nnn}/smp_affinity_list`
        done
        echo
    done
}

do_on_rps(){
    cpu_cnt=`cat /proc/cpuinfo  |grep "^processor" |wc -l`
    f_num=$(($cpu_cnt/4))
    if [[ $f_num -gt 32 ]];then
        f_num=8
    fi
    echo_string=`for i in $(seq 1 $f_num);do echo -ne "f";done`
    if [[ $echo_string"X" == "X" && $cpu_cnt = "2" ]];then
        echo_string="3"
    elif [[ $echo_string"X" == "X" && $cpu_cnt = "3" ]];then
        echo_string="7"
    fi
    total_queue=0
    for nic in `get_up_nic`;do
        rx_num=`cat /proc/interrupts |grep -iE "$nic-.*rx" |wc -l`
        total_queue=$(($total_queue+$rx_num))
    done

    queue_flow_cnt=$((2048/$total_queue))
    sysctl -w net.core.rps_sock_flow_entries=2048 >/dev/null


    for nic in `get_up_nic`;do
        echo "`date "+%F %T"` Info: enable $nic RPS/RFS"
        rx_num=`cat /proc/interrupts |grep -iE "$nic-.*rx" |wc -l`
        for num in `seq 0 $(($rx_num-1))`;do
            echo $echo_string > /sys/class/net/$nic/queues/rx-${num}/rps_cpus
            echo $queue_flow_cnt > /sys/class/net/$nic/queues/rx-${num}/rps_flow_cnt
        done
    done
}

do_off_rps(){
    sysctl -w net.core.rps_sock_flow_entries=0 >/dev/null
    for nic in `get_up_nic`;do
        echo "`date "+%F %T"` Info: disable $nic RPS/RFS"
        rx_num=`cat /proc/interrupts |grep -iE "$nic-.*rx" |wc -l`
        for num in `seq 0 $(($rx_num-1))`;do
            echo 0 > /sys/class/net/$nic/queues/rx-${num}/rps_cpus
            echo 0 > /sys/class/net/$nic/queues/rx-${num}/rps_flow_cnt
        done
    done
}

help(){
    echo "Usage: "
    echo -e "\t $0 -s  [Set IRQ smp_affinity for all working NICs]"
    echo -e "\t $0 -l  [List IRQ smp_affinity for all working NICs]"
    echo -e "\t $0 -e  [Enable RPS/RFS]"
    echo -e "\t $0 -d  [Disable RPS/RFS]"
    echo -e "\t $0 -a  [Set IRQ smp_affinity and enable RPS/RFS]"
    echo -e "\t $0 -h  [Get this page]"
}


if [[ $1 != "-a" && $1 != "-h" && $1 != "-s" && $1 != "-l" && $1 != "-e" && $1 != "-d" ]];then
    help
elif [[ $1 == "-h" ]];then
    help
elif [[ $1 == "-s" ]];then
    do_set
elif [[ $1 == "-l" ]];then
    do_list
elif [[ $1 == "-e" ]];then
    do_on_rps
elif [[ $1 == "-d" ]];then
    do_off_rps
elif [[ $1 == "-a" ]];then
    do_set
    do_on_rps
fi

