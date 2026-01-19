#/bin/sh

LOG="/tmp/$(date +%Y%m%d%s).dnsmega.log"

function log_info { printf "[INFO]: $@ \n">>$LOG ; } 
function log_err  { printf "[ERR ]: $@ \n">>$LOG ; }
function log_pass { printf "[PASS]: $@ \n">>$LOG ; }
function log_fail { printf "[FAIL]: $@ \n">>$LOG ; }
function log_dump { printf "[DUMP]: Dump of $1:\n">>$LOG; cat $1>>$LOG ; printf "\n" >>$LOG;}

#
# DES:
#   Main test function to run dig CMD.
#
# INPUT: 
# $1: query domain name
# $2: query type
# $3: DNS server IP/HOSTNAME
# $rest: dig parameters
#
function main_test {
#    typeset DNS_TYPE=$2
    typeset DNS_SERVER=$1
    typeset DOMN=$2
    shift 2
    typeset dig_opt=$@
    
    typeset tmp_err=$(mktemp)
    typeset tmp_std=$(mktemp)

    cmd="dig @$DNS_SERVER -q \"$DOMN\" $dig_opt"

    log_info""
    log_info "RUM CMD: $cmd"
    eval time $cmd >$tmp_std 2>$tmp_err
    ret=$?
    log_info""

    if (( ret == 0 )); then
        log_pass "$cmd"
        log_dump $tmp_std
    else
        log_fail "$cmd"
        log_dump $tmp_err
        return 1
    fi

    rm -f $tmp_std
    rm -f $tmp_err

    log_info""
    return 0
}

#
# Compare the return value with 114.114.114.114
#
function dig_check_result
{
    typeset DNS_SERVER=$1
    typeset DOMN=$2
    shift 2
    typeset dig_opt=$@
    
    typeset tmp_err=$(mktemp)
    typeset tmp_std=$(mktemp)
    typeset tmp_err2=$(mktemp)
    typeset tmp_std2=$(mktemp)

    cmd="dig @$DNS_SERVER -q \"$DOMN\" $dig_opt"
    cmd2="dig @$OTHER_DNS_SERVER -q \"$DOMN\" $dig_opt"

    log_info""
    log_info "RUM CMD: $cmd" 
    eval time $cmd >$tmp_std 2>$tmp_err
    ret=$?
    log_info""
    log_info "RUM CMD: $cmd2" 
    eval time $cmd2 >$tmp_std2 2>$tmp_err2
    ret2=$?
    log_info""

    if (( ret == 0 && ret2 == 0 )); then
	    result1=$(cat $tmp_std |grep HEADER |awk -F"," '{print $2}' |awk -F":" '{print $2}')
	    result2=$(cat $tmp_std |grep HEADER |awk -F"," '{print $2}' |awk -F":" '{print $2}')
	    if [[ $result1 == $result2 ]]; then
        	log_pass "return status = $result1"
	else
		log_fail "result1 = $result1, result2 = $result2"
	fi
    else
	    if (( ret !=  ret2 )); then
		    log_fail "ret1 = $ret, ret2=$ret2"
	    fi
    fi

    rm -f $tmp_std
    rm -f $tmp_err
    rm -f $tmp_std2
    rm -f $tmp_err2

    log_info""
    return 0
}

function usage 
{
    printf " \n "
    printf "\tUsage:\n" 
    printf "\t digtest.sh [-s DNS_SERVER] [-c check_with_other_dns_server] \n "
    printf "\t -s DNS_SERVER: the dns server to test\n "
    printf "\t -c check_with_other_dns_server: if [-c 1], check with other local dns server will be run.\n "
    printf "\t \n "
    printf "\t \n "
}
#
# Test domains array.
# 普通递归域名
# mogu.a.com 下配置了54 个 ip
# 线上最长域名
# 泛域名
# 外部长域名
# 长qname：[63 digit].[63 digit].[63 digit].[63 digit],tatal length: 256
# 带空格、特殊字符： a\ \0\\\'\"\&\|\(\)\^\%\$\#\@\,\/\;\{\-\+\!\~.com
# 超多级域名
#
domain_arr=( "www.alipay.com" \
    "mogu.a.com" \
    "confreg.0000000001-0000014385-0000014383.dev01.alipay.net.a.com" \
    "*.a.com" \
    "1251008728.cdn.myqcloud.com" \
    "012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.0123456789012345678901234567890123456789012345678901234567890" \
    "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20.21.22.23.24.25.26.27.28.29.30.31.32.33.34.35.36.37.38.39.40.41.42.43.44.45.46.47.48.49.50.51.52.53.54.55.56.57.58.59.60.a.com." \
    )

dig_q_type_arr=("SOA" "MD" "MF" "A" \
    "MB" "MG" "MR" "NS" \
    "NULL" "WKS" "CNAME" "PTR" \
    "HINFO" "MINFO" "MX" "TXT" \
    "AXFR" "MAILB" "MAILA" "any" \
    )

#dig_q_class_arr=( " " \
#	"-c in" \
#	"-c hs" \
#	"-c ch" \
#	)

# AA flag has no meaning in "query package"
#dig_d_opt_aaflag=(" " \
#	"+aaonly" \
#	"+noaaonly" \
#	)

#dig_d_opt_adflag=(" " \
#	"+noadflag" \
#	"adflag" \
#	)

dig_d_opt_rd=( \
	"+norecurse" \
	"+recurse" \
	)

dig_d_opt_dnssec=( \
	"+nodnssec" \
	"+dnssec" \
	)

dig_d_opt_tcp=( \
	"+notcp" \
	"+tcp" \
	)

dig_d_opt_edns=(" " \
	"+bufsize=0" \
	"+bufsize=65535" \
	"+edns=0" \
	"+edns=33" \
	"+edns=255" \
	)

#
# DNS server IP.
# This IP could be IPv4 or IPv6
#
HOST="dnstest05.tbc"
CHECK_WITH_OTHER_DNS_SERVER=0
#OTHER_DNS_SERVER="114.114.114.114"
OTHER_DNS_SERVER="8.8.8.8"
while getopts s:c:h OPT; do
    case $OPT in
        s)
        HOST=$OPTARG
        ;;
        c)
        CHECK_WITH_OTHER_DNS_SERVER=$OPTARG
        ;;
        \?|h)
        usage
        exit 1
        ;;
    esac
done

printf "start testing..., please wait\n"
printf "LOG: $LOG \n"

log_info "--------  Start of test -------"
log_info ""

pass_cnt=0
fail_cnt=0
#
# main loop to run test.
#
count=0
for g in {0..1}; do
for h in {0..1}; do
for l in {0..1}; do
for k in {0..5}; do
for i in $(seq 0 $(( ${#domain_arr[@]} - 1 )) ) ; do
	for j in $(seq 0 $(( ${#dig_q_type_arr[@]} - 1 )) ) ; do
	log_info "-------- TEST $((++count))-------"
	test_cmd[$count]="dig @$HOST \
		-q ${domain_arr[$i]} \
		-t ${dig_q_type_arr[$j]} \
		${dig_d_opt_rd[$g]} \
		${dig_d_opt_dnssec[$h]} \
		${dig_d_opt_tcp[$l]} \
		${dig_d_opt_edns[$k]} \
		+short "
        main_test $HOST \
		"${domain_arr[$i]}" \
		-t ${dig_q_type_arr[$j]} \
		${dig_d_opt_rd[$g]} \
		${dig_d_opt_dnssec[$h]} \
		${dig_d_opt_tcp[$l]} \
		${dig_d_opt_edns[$k]} \
		+short
        if (( $? == 0 )); then 
            (( pass_cnt++ ))
	    result_arr[$count]="PASS"
        else 
            (( fail_cnt++ ))
	    result_arr[$count]="FAIL"
        fi
    done
done
done
done
done
done

if (( CHECK_WITH_OTHER_DNS_SERVER != 0 )); then
for g in {0..1}; do
for h in {0..1}; do
for l in {0..1}; do
for k in {0..5}; do
for i in $(seq 0 $(( ${#domain_arr[@]} - 1 )) ) ; do
	for j in $(seq 0 $(( ${#dig_q_type_arr[@]} - 1 )) ) ; do
	log_info "-------- TEST $((++count))-------"
	test_cmd[$count]="dig @$HOST \
		-q "${domain_arr[$i]}" \
		-t ${dig_q_type_arr[$j]} \
		${dig_d_opt_rd[$g]} \
		${dig_d_opt_dnssec[$h]} \
		${dig_d_opt_tcp[$l]} \
		${dig_d_opt_edns[$k]} \
		+short "
        dig_check_result $HOST \
		"${domain_arr[$i]}" \
		-t ${dig_q_type_arr[$j]} \
		${dig_d_opt_rd[$g]} \
		${dig_d_opt_dnssec[$h]} \
		${dig_d_opt_tcp[$l]} \
		${dig_d_opt_edns[$k]} \
		+short
        if (( $? == 0 )); then 
            (( pass_cnt++ ))
	    result_arr[$count]="PASS"
        else 
            (( fail_cnt++ ))
	    result_arr[$count]="FAIL"
        fi
    done
done
done
done
done
done
fi

log_info ""
log_info "--------  End of test -------"
log_info "--------  Stat of test -------"
log_info "Total: $(( pass_cnt + fail_cnt )), PASS: $(( pass_cnt )), FAIL: $(( fail_cnt )) "
for i in $(seq 1 $count); do
	if [[ ${result_arr[$i]} == "FAIL" ]]; then
		log_fail "Test ${i}: ${result_arr[$i]}"
		log_fail "CMD: ${test_cmd[$i]}"
	fi
done
