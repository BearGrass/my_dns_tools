#!/bin/bash
export BASE=/work/dpdk_fwrd/scripts
export FWDCTL=/work/dpdk_fwrd/bin/fwdctl
export ACTIVE=/work/dpdk_fwrd/scripts/reg.active
export LOG=$BASE/protect.log
function msg()
{
        message=$1
        echo "`date '+%F_%T'` - ${message}" >> ${LOG} 2>&1
        echo "`date '+%F_%T'` - ${message}" 
}
function fwdctl_exec()
{
	msg "$1"
	/bin/bash -c "$1"
}

function fwdctl_regex()
{
	local regexStr="$1"
	local cmd="$FWDCTL  -s 127.0.0.1 -p 6666 protect_start \"$regexStr\""
	fwdctl_exec "$cmd"
}

function fwdctl_regex_del()
{
	local regexStr="$1"
	local cmd="$FWDCTL  -s 127.0.0.1 -p 6666 delreg \"$regexStr\""
	fwdctl_exec "$cmd"
	echo "$regexStr" >$ACTIVE
}
function fwdctl_del_all()
{
	local cmd="$FWDCTL  -s 127.0.0.1 -p 6666 del all"
	fwdctl_exec "$cmd"
}


function protectAll()
{

        msg "start protect all"
	fwdctl_regex "*:.*"
	fwdctl_del_all
        msg "working on protect all"
}
function protectViewAll()
{
	msg "start protect all keys in View [$1]"
	fwdctl_regex "$1:.*"
	fwdctl_regex_del "$1:.*"
	msg "working on  protect all keys in View [$1]"
}

function generateSingleRegex()
{
	local vname="*"
	local domain="$1"
	local step=""
	if [ "x$2" != "x" ] ; then
		vname=$2
	fi
	
	domain="$1"
	
	####
	#如果用户对这个域写了“.”结尾，则去掉这个“.” 号
	####
	step=`echo "$domain"|sed 's/\.$//'`  
	#echo "$step"

	###
	#把“.”替换为"\."以供正则表达式来匹配域名中的“.”号
	###
	step=`echo "$step"|sed 's/\./\\\./g'`
	#echo "$step"
	
	###
	#1.  baidu.com./2 要能匹配到，即ns记录要能匹配到
	#2.  www.baidu.com./1 不要能匹配到，即要精确匹配这个域名即可
	#3.  abaidu.com./2 不能匹配到
	##
	step="^$step\./*"
	#msg "active regex [$step]"
	
	###
	#view的名字如果设置为“*”,fwd_dns_dpdk里面对“*”识别为所有的view生效
	###
	step="$vname:$step"
	echo "$step"
}
function generateDomainRegex()
{
	local vname="*"
	local domain="$1"
	local step=""
	if [ "x$2" != "x" ] ; then
		vname=$2
	fi
	
	domain="$1"
	
	####
	#如果用户对这个域写了“.”结尾，则去掉这个“.” 号
	####
	step=`echo "$domain"|sed 's/\.$//'`  
	#echo "$step"

	###
	#把“.”替换为"\."以供正则表达式来匹配域名中的“.”号
	###
	step=`echo "$step"|sed 's/\./\\\./g'`
	#echo "$step"
	
	###
	#两种情况匹配到这个域下所有类型，以baidu.com为例
	#1.  baidu.com./2 要能匹配到，即ns记录要能匹配到
	#2.  www.baidu.com./1 要能匹配到，即所有以baidu.com结尾的所有域名类型都能匹配到
	#而 abaidu.com./2 则不能匹配到
	##
	#step="(.*\.|^)$step\./*"
	step=".*\.$step\./*"
	#msg "active regex [$step]"
	
	###
	#把view的名字如果设置为“*”,fwd_dns_dpdk里面对“*”识别为所有的view生效
	###
	step="$vname:$step"
	echo "$step"
}

function protectDomain()
{
	
        msg "start domain protect for [$1]"

	local regexStr=`generateDomainRegex "$1"`
	msg "active last fwdctl string [$regexStr]"

	fwdctl_regex "$regexStr"
	fwdctl_regex_del "$regexStr"

        msg "working on domain protect for [$1]"
	###
}

function protectViewDomain()
{
	
        msg "start view domain protect for [$1]"
	local vname=`echo "$1"|awk -F ':' '{print $1}'`
	local str=`echo "$1"|awk -F ':' '{print $2}'`
	
	local regexStr=`generateDomainRegex "$str" "$vname"`
	msg "active last fwdctl string [$regexStr]"

	fwdctl_regex "$regexStr"
	fwdctl_regex_del "$regexStr"

        msg "working on domain protect for [$1]"
	###
}

function protectSingle()
{
        msg "start single domain name protect for [$1]"
	local regexStr=`generateSingleRegex "$1"`
	msg "active last fwdctl string [$regexStr]"
	fwdctl_regex "$regexStr"
	fwdctl_regex_del "$regexStr"
        msg "working on single domain name protect for [$1]"
}

function protectViewSingle()
{
	
        msg "start single key protect for [$1]"
	local vname=`echo "$1"|awk -F ':' '{print $1}'`
	local str=`echo "$1"|awk -F ':' '{print $2}'`
	
	local regexStr=`generateSingleRegex "$str" "$vname"`
	msg "active last fwdctl string [$regexStr]"

	fwdctl_regex "$regexStr"
	fwdctl_regex_del "$regexStr"

        msg "working on single protect for [$1]"
	###
}
function protectStop()
{
	cmd="$FWDCTL  -s 127.0.0.1 -p 6666 protect_stop"
	fwdctl_exec "$cmd"
	msg "Protecting mode ending, recover forwarder answer from cdn dns"
	regexStr=`cat $ACTIVE`;
	if [ "x$regexStr"  == "x" ]  ; then
		msg "nothing to do"
	else
		msg "Protecting mode ending, del $regexStr "
		fwdctl_regex_del "$regexStr"
	fi
	rm -f $ACTIVE
	msg "Protected mode end"
}

function usage()
{
	echo "control protect ,mode 1(work in all view)    input single string       | domain string       | all "
	echo "control protect ,mode 2(work in single view) input vsingle view:string | vdomain view:string | vall viewName "
	echo "control protect ,mode 3(stop protect)        input stop"

}
function run()
{
	action=$1
	if [ -z ${action} ] ; then
		usage;
		exit 1;
	fi
	
	keys=("single vsingle domain vdomain all vall stop")
	ok=0

	for sk in ${keys[@]} ; do
		if [ "x$action" == "x$sk" ] ; then
			ok=1;
			break;
		fi
	done
	
	if [ $ok -eq 0 ] ; then
		usage 
		exit 1;
	fi
		
	if [ "$action" != "all" -a "$action" != "stop" -a "x$2" == "x" ] ; then
		usage
		exit 1
	fi	

	case ${action} in
        single)
	protectSingle "$2"
        ;;
        vsingle)
	protectViewSingle "$2"
        ;;
        domain)
        protectDomain "$2"
        ;;
        vdomain)
        protectViewDomain "$2"
        ;;
        all)
	protectAll
        ;;
        vall)
	protectViewAll "$2"
        ;;
	stop)
	protectStop
	;;
esac
}

run $@
