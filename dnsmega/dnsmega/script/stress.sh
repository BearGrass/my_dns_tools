#!/bin/bash

#
# Global variables.
#
LOG="/tmp/$(date +%Y%m%d%s).dnsmega.stress.log"
# This two variable is used to control the stress of tcpreplay
MAX_QPS=10000
# Check times for each test.
CHECK=5

loop=10
# The threshhold for counter named with prefix "err"
ERR_THRESHHOLD=10 
tmp_flow=$(mktemp)

function log_info { printf "[INFO]: $@\n">>$LOG ; } 
function log_err  { printf "[ERR ]: $@\n">>$LOG ; }
function log_pass { printf "[PASS]: $@\n">>$LOG ; }
function log_fail { printf "[FAIL]: $@\n">>$LOG ; }
function log_dump { printf "[DUMP]: Dump of $1:\n">>$LOG; cat $1>>$LOG ; printf "\n" >>$LOG;}


function usage
{
    printf " \n "
    printf "\tUsage:\n" 
	printf "\tThis script must be run in root user mode.\n"
	printf "\tAnd ssh root without password from test machine to DNS server must be set!\n" 
    printf " \n "
    printf "\tstress.sh -f pcap -s server [-l loop] [-m maxqps] [-h]\n"
    printf "\tINPUT: \n"
    printf "\t\t-f pcap: pcap file, should have been modified to use without any change \n"
    printf "\t\t-l loop: the loop of each tcpreplay CMD \n"
    printf "\t\t-m maxqps: maxqps for tcpreplay \n"
    printf "\t\t-c: check times for each test, by default it is 5, should be smaller than 50\n"
    printf " \n "
	printf "\texample: \n"
	printf "\t\tsudo sh -x stress.sh -f ddos.pcap_1 -s 10.97.212.33\n"
    printf " \n "
}


while getopts f:s:t:m:c:h OPT; do
    case $OPT in
        f)
        pcap_file=$OPTARG
        ;;
        s)
        server=$OPTARG
        ;;
        t)
        loop=$OPTARG
        ;;
        m)
        MAX_QPS=$OPTARG
        ;;
        c)
        CHECK=$OPTARG
        ;;
        \?|h)
        usage
        exit 1
        ;;
    esac
done

if [[ -z $pcap_file || -z $server ]]; then
    printf "Must specify pcap file and server ip!\n"
    exit 1
fi

if (( $CHECK >50 )); then
	printf "Must be smaller then 50!\n"
	exit 1
fi

SSH="ssh root@$server"

counter_list=( \
    "accept_local_in_l3" \
    "accept_local_in_l4" \
    "accept_local_in_l7" \
    "accept_linearize_in" \
    "accept_local_out_l3" \
    "accept_local_out_l4" \
    "accept_local_out_l7" \
    "accept_linearize_out" \
    "accept_loopback_out" \
    "accept_nosupport" \
    "drop_singleip_ratelimit" \
    "drop_pac_incomplete" \
    "drop_pac_oversize" \
    "drop_parse_error" \
    "drop_waitlist_full" \
    "drop_forward_ratelimit" \
    "drop_nomem_request" \
    "drop_genpac_error" \
    "request_in" \
    "request_out" \
    "request_hit" \
    "request_hold" \
    "request_prefetch" \
    "cache_expired" \
    "error_nomem_request" \
    "error_nomen_skb" \
    "error_big_append" \
    "error_update_rt" \
    "error_cow_head" \
    "error_response_no_cache" \
    "error_nomem_node" \
    "error_nomem_node_val" \
    "error_nomem_node_key" \
    "fwd_logic_response" \
    "fwd_real_response" \
    "fwd_real_timeout" \
    "fwd_queries"
)

function tcpreplay_traffic
{
    typeset pcap=$1
    typeset tmp_std=$2
    shift 2
    typeset cmd_opt=$@

    cmd="tcpreplay $cmd_opt $pcap"

    log_info""
    log_info "RUM CMD: $cmd"
    eval $cmd >$tmp_std 2>&1 &
    log_info""

    return 0
}
function queryperf_traffic
{
    typeset cmd=$@

    log_info""
    log_info "RUM CMD: $cmd" 
    eval $cmd >/dev/null 2>&1 &
    log_info""

    return 0
}

function check_counter
{
    typeset interval=$1
    typeset loop=$2
    
    #
    # Check on dns server.
    #
    for i in $(seq 1 $loop); do
        typeset tmp_err1=$(mktemp)
        typeset tmp_std1=$(mktemp)
        typeset tmp_err2=$(mktemp)
        typeset tmp_std2=$(mktemp)

        log_info "loop $i, calculate the incease of each counter in one second:"
        $SSH "cat /proc/dnsmega/counters" >$tmp_std1 2>$tmp_err1
        sleep $interval
        $SSH "cat /proc/dnsmega/counters" >$tmp_std2 2>$tmp_err2

		typeset fail_flag=0
        for element in $(seq 0 $((${#counter_list[@]} - 1))); do
            cnt2=$(grep -w ${counter_list[$element]} $tmp_std2 | awk -F":" '{print $2}') 
            cnt1=$(grep -w ${counter_list[$element]} $tmp_std1 | awk -F":" '{print $2}') 
            minus=$(( cnt2 - cnt1 ))
			if $(echo ${counter_list[$element]} |grep -q err); then
				if (( minus > $ERR_THRESHHOLD )); then
					((fail_flag++))
					log_err "${counter_list[$element]} = ${minus}"
				else
            		log_info "${counter_list[$element]} = ${minus}"
				fi
			else
            	log_info "${counter_list[$element]} = ${minus}"
			fi
        done
        log_info ""

        rm -f $tmp_std1
        rm -f $tmp_err1
        rm -f $tmp_std2
        rm -f $tmp_err2

		if (( fail_flag != 0 )); then
			log_fail "one error is larger than 10!"
			return 1
		fi

    done
}

#
# Main test loop
#
function test_startup
{
    log_info "Clean legacy tcpreplay and queryperf on client"
    pkill tcpreplay >/dev/null 2>&1
    #pkill queryperf >/dev/null 2>&1
    
    log_info "clear counter on server"
    $SSH "echo 1 >/proc/dnsmega/clear_counters"
}

function test_cleanup
{
    log_info "Clean legacy tcpreplay and queryperf on client"
	#
	# Here must use "-2" option to specify signal :SIGINT, so as to make
	# tcpreplay print log.
	#
    pkill -2 tcpreplay >/dev/NULL 2>&1
    # sleep 5s to make sure tcpreplay has fininshed writing log.
    sleep 5
    log_info "tcpreplay log is:"
    log_dump $tmp_flow
    #pkill queryperf >/dev/null 2>&1
}

#
# With little stress
#
function test1 
{
	test_startup

    log_info "Generate stress in background."
    tcpreplay_traffic $pcap_file "$tmp_flow" -l 10000 -p 100000 --intf1=bond0

    pgrep tcpreplay >/dev/null 2>&1
    if (( $? != 0 )); then
	    log_err "tcpreplay is not launched, info is here:"
	    log_dump $tmp_flow
	    exit 1
    fi

	log_info "+++ Start test1 +++"
    check_counter 1 2
    ret=$?

	test_cleanup

	log_info "+++ End test1 +++"

    return $ret
}

function test2
{
	test_startup

    log_info "Generate stress in background."
    tcpreplay_traffic $pcap_file $tmp_flow -l 10000 -p 1000000 --intf1=bond0

    pgrep tcpreplay >/dev/null 2>&1
    if (( $? != 0 )); then
	    log_err "tcpreplay is not launched, info is here:"
	    log_dump $tmp_flow
	    exit 1
    fi

	log_info "+++ Start test2 +++"
    check_counter 1 $CHECK
    ret=$?

	test_cleanup

	log_info "+++ End test2 +++"

    return $ret
}

function test3
{
	test_startup

    log_info "Generate stress in background."
    tcpreplay_traffic $pcap_file $tmp_flow -l 10000 -p 2000000 --intf1=bond0

    pgrep tcpreplay >/dev/null 2>&1
    if (( $? != 0 )); then
	    log_err "tcpreplay is not launched, info is here:"
	    log_dump $tmp_flow
	    exit 1
    fi

	log_info "+++ Start test3 +++"
    check_counter 1 $CHECK
    ret=$?

	test_cleanup

	log_info "+++ End test3 +++"

    return $ret
}

function test4
{
	test_startup

    log_info "Generate stress in background."
    tcpreplay_traffic $pcap_file $tmp_flow -l 10000 -p 3000000 --intf1=bond0

    pgrep tcpreplay >/dev/null 2>&1
    if (( $? != 0 )); then
	    log_err "tcpreplay is not launched, info is here:"
	    log_dump $tmp_flow
	    exit 1
    fi

	log_info "+++ Start test4 +++"
    check_counter 1 $CHECK
    ret=$?

	test_cleanup

	log_info "+++ End test4 +++"

    return $ret
}

function test5
{
	test_startup

    log_info "Generate stress in background."
    typeset tmp_flow=$(mktemp)
    tcpreplay_traffic $pcap_file $tmp_flow -l 10000 -p 3500000 --intf1=bond0

    pgrep tcpreplay >/dev/null 2>&1
    if (( $? != 0 )); then
	    log_err "tcpreplay is not launched, info is here:"
	    log_dump $tmp_flow
	    exit 1
    fi

	log_info "+++ Start test5 +++"
    check_counter 1 $CHECK
    ret=$?

	test_cleanup

	log_info "+++ End test5 +++"

    return $ret
}

function test6
{
	test_startup

    log_info "Generate stress in background."
    tcpreplay_traffic $pcap_file $tmp_flow -l 10000 -p 4000000 --intf1=bond0

    pgrep tcpreplay >/dev/null 2>&1
    if (( $? != 0 )); then
	    log_err "tcpreplay is not launched, info is here:"
	    log_dump $tmp_flow
	    exit 1
    fi

	log_info "+++ Start test6 +++"
    check_counter 1 $CHECK
    ret=$?

	test_cleanup

	log_info "+++ End test6 +++"

    return $ret
}

#
# Single DNS request stress test
#
function test7
{
	test_startup

    log_info "Generate stress in background."
	tcpreplay_traffic dns.pcap $tmp_flow -l 10000000 \
        -p 1000000 --intf1=bond0

    pgrep tcpreplay >/dev/null 2>&1
    if (( $? != 0 )); then
	    log_err "tcpreplay is not launched, info is here:"
	    log_dump $tmp_flow
	    exit 1
    fi

	log_info "+++ Start test7 +++"
    check_counter 1 $CHECK
    ret=$?

	test_cleanup

	log_info "+++ End test7 +++"

    return $ret
}

#
# 观察大量队列链表操作
# echo 1 > /proc/dnsmega/barely_trusted_time
# echo 1 > /proc/dnsmega/expired_time
function test8
{
	test_startup

    log_info "Generate stress in background."
    tcpreplay_traffic $pcap_file $tmp_flow -l 10000 -p 400000 --intf1=bond0
    pgrep tcpreplay >/dev/null 2>&1
    if (( $? != 0 )); then
	    log_err "tcpreplay is not launched, info is here:"
	    log_dump $tmp_flow
	    exit 1
    fi

	log_info "+++ Start test8 +++"
	
	typeset trust_time=$($SSH \
		"cat /proc/dnsmega/barely_trusted_time")
	typeset expired_time=$($SSH \
		"cat /proc/dnsmega/expired_time")
	$SSH "echo 1 > /proc/dnsmega/barely_trusted_time"
	$SSH "echo 1 > /proc/dnsmega/expired_time"
    check_counter 1 $CHECK
    ret=$?

	$SSH "echo $trust_time > /proc/dnsmega/barely_trusted_time"
	$SSH "echo $expired_time > /proc/dnsmega/expired_time"

	test_cleanup

	log_info "+++ End test8 +++"

    return $ret
}

# 观察非正常域名请求丢包情况
# echo 0 > /proc/dnsmega/max_req_waitlist_num
function test9
{
	test_startup

    log_info "Generate stress in background."
    tcpreplay_traffic $pcap_file $tmp_flow -l 10000 -p 400000 --intf1=bond0
    pgrep tcpreplay >/dev/null 2>&1
    if (( $? != 0 )); then
	    log_err "tcpreplay is not launched, info is here:"
	    log_dump $tmp_flow
	    exit 1
    fi

	log_info "+++ Start test9 +++"
	
	typeset max_wait=$($SSH \
		"cat /proc/dnsmega/max_req_waitlist_num")
	$SSH \
		"echo 0 > /proc/dnsmega/max_req_waitlist_num"
    check_counter 1 $CHECK
    ret=$?

	$SSH \
		"echo $max_wait > /proc/dnsmega/max_req_waitlist_num"

	test_cleanup

	log_info "+++ End test9 +++"

    return $ret
}


log_info "------ Start of test ------"
echo "------ Start of test ------"
echo "Log: $LOG"

log_info "Check if tcpreplay is installed... "
which tcpreplay >/dev/null 2>&1
(( $? != 0 )) && log_err "tcpreplay is not installed!" && exit 1

pass_cnt=0
fail_cnt=0

for i in {1..9}; do
	test$i
	if (( $? == 0 )); then
	    (( pass_cnt++ ))
	    result_arr[$i]="PASS"
	else
	    (( fail_cnt++ ))
	    result_arr[$i]="FAIL"
	fi
done

log_info ""
log_info "--------  End of test -------"
log_info "Total: $(( pass_cnt + fail_cnt )), PASS: $(( pass_cnt )), FAIL: $(( fail_cnt )) "

for i in $(seq 1 ${#result_arr[@]}); do
	if [[ result_arr[$i] == "FAIL" ]]; then
		log_fail "TEST $i "
	fi
done
rm $tmp_flow
