#/bin/sh

LOG="/tmp/$(date +%Y%m%d%s).dnsmega.log"

function log_info { printf "[INFO]: $@\n">>$LOG ; } 
function log_err  { printf "[ERR ]: $@\n">>$LOG ; }
function log_pass { printf "[PASS]: $@\n">>$LOG ; }
function log_fail { printf "[FAIL]: $@\n">>$LOG ; }
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
    typeset DOMN=$1
    typeset DNS_TYPE=$2
    typeset DNS_SERVER=$3
    shift 3
    typeset dig_opt=$@
    
    typeset tmp_err=$(mktemp)
    typeset tmp_std=$(mktemp)

    cmd="dig $DOMN $DNS_TYPE @$DNS_SERVER $dig_opt"

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
# Test domains array.
# 普通递归域名
# mogu.a.com 下配置了54 个 ip
# 线上最长域名
# 泛域名
# 外部长域名
# ANY 请求
# 长qname：[63 digit].[63 digit].[63 digit].[63 digit],tatal length: 256
# 带‘-’的qname：a-b-0-d-2-e-.com
# 带空格、特殊字符： a\ \0\\\'\"\&\|\(\)\^\%\$\#\@\,\/\;\{\-\+\!\~.com
# 超多级域名
#
domain_arr=( "www.alipay.com" \
    "mogu.a.com" \
    "confreg.0000000001-0000014385-0000014383.dev01.alipay.net.a.com" \
    "*.a.com" \
    "1251008728.cdn.myqcloud.com" \
    "aliyun.com" \
    "012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.012345678901234567890123456789012345678901234567890123456789012.0123456789012345678901234567890123456789012345678901234567890" \
    "a-b-0-d-2-e-.com" \
    "a\ \0\\\'\"\&\|\(\)\^\%\$\#\@\,\/\;\{\-\+\!\~.com" \
    "1.2.3.4.5.6.7.8.9.10.11.12.13.14.15.16.17.18.19.20.21.22.23.24.25.26.27.28.29.30.31.32.33.34.35.36.37.38.39.40.41.42.43.44.45.46.47.48.49.50.51.52.53.54.55.56.57.58.59.60.a.com." \
    )

type_arr=("SOA" "MD" "MF" "A" \
    "MB" "MG" "MR" "NS" \
    "NULL" "WKS" "CNAME" "PTR" \
    "HINFO" "MINFO" "MX" "TXT" \
    "AXFR" "MAILB" "MAILA" \
    )

#
# DNS server IP.
#
HOST=${1:-"dnstest05.tbc"}

printf "start testing..., please wait\n"
printf "LOG: $LOG \n"

log_info "--------  Start of test -------"
log_info ""

pass_cnt=0
fail_cnt=0
#
# main loop to run test.
#
for i in {0..7} ; do
    for j in {0..18} ; do
        main_test ${domain_arr[$i]} ${type_arr[j]} $HOST +short
        if (( $? == 0 )); then 
            (( pass_cnt++ ))
        else 
            (( fail_cnt++ ))
        fi
    done
done

log_info ""
log_info "Total: $(( pass_cnt + fail_cnt )), PASS: $(( pass_cnt )), FAIL: $(( fail_cnt )) "
log_info "--------  End of test -------"
