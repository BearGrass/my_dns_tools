BASE="/home/yansu.yys/work/etest/config/apdns/protect"

CONF="$BASE/fwd_dns_user.conf"
LOG="$BASE/protect.log"
PARSE="$BASE/parse.sh"
VIEW="$BASE/views.conf"
fwderlist=("forwarder09.pdns.cm10")
redislist=("fcache01.pdns.cm10 fcache02.pdns.cm10")

INFO="$BASE/INFO"

function msg()
{
        message=$1
        echo "`date '+%F_%T'` - ${message}" >> ${LOG} 2>&1
        echo "`date '+%F_%T'` - ${message}" 
}
function err()
{
	msg "$1"
	exit 1
}

function redis_save()
{
	
	for redis in ${redislist[@]} ; do
		msg "ssh $redis \"sh /home/work/redis/scripts/rdsctl.sh save\""
		ssh $redis "sh /home/work/redis/scripts/rdsctl.sh save"
	done
}

function bind_single_flush()
{

	###
	#clean bind dns cache
	###
	/bin/sh $PARSE $CONF $VIEW
	source $VIEW;		

	msg "---BIND FLUSH BEGIN---"
	for view in ${viewlist[@]} ; do
		msg "GOTO BIND VIEW [$view]"
		hosts=$(eval "echo \$$view");
		for ip in ${hosts[@]} ;do
			msg "ssh ming.tang@$ip \"/bin/sh /home/work/dns/flush.sh single $gname\""
			ssh ming.tang@$ip "/bin/sh /home/work/dns/flush.sh single $gname"
		done
	done
}

function bind_domain_flush()
{

	###
	#clean bind dns cache
	###
	/bin/sh $PARSE $CONF $VIEW
	source $VIEW;		

	msg "---BIND FLUSH BEGIN---"
	for view in ${viewlist[@]} ; do
		msg "GOTO BIND VIEW [$view]"
		hosts=$(eval "echo \$$view");
		for ip in ${hosts[@]} ;do
			msg "ssh ming.tang@$ip \"/bin/sh /home/work/dns/flush.sh domain $gname\""
			ssh ming.tang@$ip "/bin/sh /home/work/dns/flush.sh domain $gname"
		done
	done
}
function bind_all_flush()
{

	###
	#clean bind dns cache
	###
	/bin/sh $PARSE $CONF $VIEW
	source $VIEW;		

	msg "---BIND FLUSH BEGIN---"
	for view in ${viewlist[@]} ; do
		msg "GOTO BIND VIEW [$view]"
		hosts=$(eval "echo \$$view");
		for ip in ${hosts[@]} ;do
			msg "ssh ming.tang@$ip \"/bin/sh /home/work/dns/flush.sh all\""
			ssh ming.tang@$ip "/bin/sh /home/work/dns/flush.sh all"
		done
	done
}
function bind_vsingle_flush()
{

	local name="$1"
	###
	#clean bind dns cache
	###
	/bin/sh $PARSE $CONF $VIEW
	source $VIEW;		

	msg "---BIND FLUSH BEGIN---"
	for view in ${viewlist[@]} ; do
		if [ "x$view" == "x$gview" ] ; then
			msg "GOTO BIND VIEW [$view]"
			hosts=$(eval "echo \$$view");
			for ip in ${hosts[@]} ;do
				msg "ssh ming.tang@$ip \"/bin/sh /home/work/dns/flush.sh single $name\""
				ssh ming.tang@$ip "/bin/sh /home/work/dns/flush.sh single $name"
			done
			break;
		fi
	done
}
function bind_vdomain_flush()
{

	###
	#clean bind dns cache
	###
	/bin/sh $PARSE $CONF $VIEW
	source $VIEW;		

	msg "---BIND FLUSH BEGIN---"
	for view in ${viewlist[@]} ; do
		if [ "x$view" == "x$gview" ] ; then
			msg "GOTO BIND VIEW [$view]"
			hosts=$(eval "echo \$$view");
			for ip in ${hosts[@]} ;do
				msg "ssh ming.tang@$ip \"/bin/sh /home/work/dns/flush.sh domain $gname\""
				ssh ming.tang@$ip "/bin/sh /home/work/dns/flush.sh domain $gname"
			done
			break;
		fi
	done
}
function bind_vall_flush()
{

	###
	#clean bind dns cache
	###
	/bin/sh $PARSE $CONF $VIEW
	source $VIEW;		

	msg "---BIND FLUSH BEGIN---"
	for view in ${viewlist[@]} ; do
		if [ "x$view" == "x$gview" ] ; then
			msg "GOTO BIND VIEW [$view]"
			hosts=$(eval "echo \$$view");
			for ip in ${hosts[@]} ;do
				msg "ssh ming.tang@$ip \"/bin/sh /home/work/dns/flush.sh all\""
				ssh ming.tang@$ip "/bin/sh /home/work/dns/flush.sh all"
			done
			break;
		fi
	done
}
function redis_single_protect()
{
	local name="$1"
	msg "-------REDIS PROTECT BEGIN------"
	for redis in ${redislist[@]} ; do
		msg "ssh $redis \"/bin/sh  /home/work/redis/scripts/rdsctl.sh single $name\""
		ssh $redis "/bin/sh  /home/work/redis/scripts/rdsctl.sh single $name"
	done
}

function redis_domain_protect()
{
	local name="$1"
	msg "-------REDIS PROTECT BEGIN------"
	for redis in ${redislist[@]} ; do
		msg "ssh $redis \"/bin/sh  /home/work/redis/scripts/rdsctl.sh domain $name\""
		ssh $redis "/bin/sh  /home/work/redis/scripts/rdsctl.sh domain $name"
	done
}
function redis_all_protect()
{
	local name="$1"
	msg "-------REDIS PROTECT BEGIN------"
	for redis in ${redislist[@]} ; do
		msg "ssh $redis \"/bin/sh  /home/work/redis/scripts/rdsctl.sh all\""
		ssh $redis "/bin/sh  /home/work/redis/scripts/rdsctl.sh all"
	done
}
function redis_vsingle_protect()
{
	local view="$1"
	local name="$2"
	msg "-------REDIS PROTECT BEGIN------"
	for redis in ${redislist[@]} ; do
		msg "ssh $redis \"/bin/sh  /home/work/redis/scripts/rdsctl.sh vsingle $view:$name\""
		ssh $redis "/bin/sh  /home/work/redis/scripts/rdsctl.sh vsingle $view:$name"
	done
}
function redis_vdomain_protect()
{
	local view="$1"
	local name="$2"
	msg "-------REDIS PROTECT BEGIN------"
	for redis in ${redislist[@]} ; do
		msg "ssh $redis \"/bin/sh  /home/work/redis/scripts/rdsctl.sh vdomain $view:$name\""
		ssh $redis "/bin/sh  /home/work/redis/scripts/rdsctl.sh vdomain $view:$name"
	done
}
function redis_vall_protect()
{
	local view="$1"
	msg "-------REDIS PROTECT BEGIN------"
	for redis in ${redislist[@]} ; do
		msg "ssh $redis \"/bin/sh  /home/work/redis/scripts/rdsctl.sh vall $view\""
		ssh $redis "/bin/sh  /home/work/redis/scripts/rdsctl.sh vall $view"
	done
}
function fwder_single_protect()
{
	
	name="$1"
	msg "-------FORWARDER PROTECT BEGIN------"
	for fwd in ${fwderlist[@]} ; do
		msg "ssh $fwd \"/bin/sh  /work/dpdk_fwrd/scripts/protect.sh single $name\""
		ssh $fwd "/bin/sh  /work/dpdk_fwrd/scripts/protect.sh single $name"
	done
		

}

function fwder_domain_protect()
{
	
	name="$1"
	msg "-------FORWARDER PROTECT BEGIN------"
	for fwd in ${fwderlist[@]} ; do
		msg "ssh $fwd \"/bin/sh  /work/dpdk_fwrd/scripts/protect.sh domain $name\""
		ssh $fwd "/bin/sh  /work/dpdk_fwrd/scripts/protect.sh domain $name"
	done
		

}

function fwder_all_protect()
{
	
	msg "-------FORWARDER PROTECT BEGIN------"
	for fwd in ${fwderlist[@]} ; do
		msg "ssh $fwd \"/bin/sh  /work/dpdk_fwrd/scripts/protect.sh all\""
		ssh $fwd "/bin/sh  /work/dpdk_fwrd/scripts/protect.sh all"
	done
		

}

function fwder_vsingle_protect()
{
	local view="$1"
	local name="$2"
	msg "-------FORWARDER PROTECT BEGIN------"
	for fwd in ${fwderlist[@]} ; do
		msg "ssh $fwd \"/bin/sh  /work/dpdk_fwrd/scripts/protect.sh vsingle $view:$name\""
		ssh $fwd "/bin/sh  /work/dpdk_fwrd/scripts/protect.sh vsingle $view:$name"
	done
		

}
function fwder_vdomain_protect()
{
	local view="$1"
	local name="$2"
	msg "-------FORWARDER PROTECT BEGIN------"
	for fwd in ${fwderlist[@]} ; do
		msg "ssh $fwd \"/bin/sh  /work/dpdk_fwrd/scripts/protect.sh vdomain $view:$name\""
		ssh $fwd "/bin/sh  /work/dpdk_fwrd/scripts/protect.sh vdomain $view:$name"
	done
		

}
function fwder_vall_protect()
{
	local view="$1"
	msg "-------FORWARDER PROTECT BEGIN------"
	for fwd in ${fwderlist[@]} ; do
		msg "ssh $fwd \"/bin/sh  /work/dpdk_fwrd/scripts/protect.sh vall $view\""
		ssh $fwd "/bin/sh  /work/dpdk_fwrd/scripts/protect.sh vall $view"
	done
		

}
function single_protect()
{

	local name=""
	name="$1"
	msg "============BEGIN SINGLE PROTECT $name=========="
	fwder_single_protect "$name"
	redis_single_protect "$name"
	msg "============WORKING IN SINGLE PROTECT $name=========="
	
}

function domain_protect()
{

	local name=""
	name="$1"
	msg "============BEGIN DOMAIN PROTECT $name=========="
	fwder_domain_protect "$name"
	redis_domain_protect "$name"
	msg "============WORKING IN DOMAIN PROTECT $name=========="
	
}

function all_protect()
{

	local name=""
	msg "============BEGIN ALL PROTECT=========="
	fwder_all_protect 
	redis_all_protect
	msg "============WORKING IN ALL PROTECT=========="
	
}
function vsingle_protect()
{

	local view="$1"
	local name="$2"
	msg "============BEGIN VSINGLE PROTECT [$view:$name]=========="
	fwder_vsingle_protect "$view" "$name"
	redis_vsingle_protect "$view" "$name"
	msg "============WORKING IN VSINGLE PROTECT [$view:$name]=========="
	
}

function vdomain_protect()
{

	local view="$1"
	local name="$2"
	msg "============BEGIN VDOMAIN PROTECT [$view:$name]=========="
	fwder_vdomain_protect "$view" "$name"
	redis_vdomain_protect "$view" "$name"
	msg "============WORKING IN VDOMAIN PROTECT [$view:$name]=========="
	
}

function vall_protect()
{

	local view="$1"
	msg "============BEGIN VALL PROTECT [$view]=========="
	fwder_vall_protect "$view"
	redis_vall_protect "$view"
	msg "============WORKING IN VALL PROTECT [$view]=========="
	
}
function fwder_end()
{

	msg "-------FORWARDER PROTECT END------"
	for fwd in ${fwderlist[@]} ; do
		msg "ssh $fwd \"/bin/sh  /work/dpdk_fwrd/scripts/protect.sh stop\""
		ssh $fwd "/bin/sh  /work/dpdk_fwrd/scripts/protect.sh stop"
	done
}

function cache_end()
{
	msg "-------REDIS PROTECT END------"
	for redis in ${redislist[@]} ; do
		msg "ssh $redis \"/bin/sh  /home/work/redis/scripts/rdsctl.sh stop\""
		ssh $redis "/bin/sh  /home/work/redis/scripts/rdsctl.sh stop"
	done
	
}

function bind_end()
{
	if [ ! -f $INFO ] ; then
		msg "nothing to do"
		return
	fi

	source $INFO
	msg "-------BIND PROTECT END------"
	if [ "x$gmode" == "xsingle" ] ; then
		bind_single_flush 
	fi

	
	if [ "x$gmode" == "xvsingle" ] ; then
		bind_vsingle_flush 
	fi

	if [ "x$gmode" == "xdomain" ] ; then
		bind_domain_flush 
	fi

	
	if [ "x$gmode" == "xvdomain" ] ; then
		bind_vdomain_flush 
	fi
	if [ "x$gmode" == "xall" ] ; then
		bind_all_flush 
	fi

	
	if [ "x$gmode" == "xvall" ] ; then
		bind_vall_flush 
	fi
	rm -f $INFO
	msg "-------BIND PROTECT END------"
}

function protect_end()
{
	fwder_end
	cache_end
	bind_end
}

function run()
{
	if [ "x$1" == "xsave" ] ; then
		redis_save
		exit 0
	fi

	if [ "x$1" == "xsingle" ] ; then
		if [ "x$2" == "x" ] ; then
			err "single protect,need domainname arg"	
		fi

		echo "gmode=single" >$INFO
		echo "gname=$2">>$INFO
		single_protect "$2"
		exit 0
	fi
	
	
	if [ "x$1" == "xdomain" ] ; then
		if [ "x$2" == "x" ] ; then
			err "domain protect,need domainname arg"	
		fi

		echo "gmode=domain" >$INFO
		echo "gname=$2">>$INFO
		domain_protect "$2"
		exit 0
	fi
	
	if [ "x$1" == "xall" ] ; then
		echo "gmode=all" >$INFO
		all_protect
		exit 0
	fi

	if [ "x$1" == "xvsingle" ] ; then
		if [ "x$2" == "x" ] ; then
			err "vsingle protect,need view arg"	
		fi
		
		if [ "x$3" == "x" ] ; then
			err "vsingle protect,need domainname arg"
		fi
			
		echo "gmode=vsingle" >$INFO
		echo "gview=$2" >> $INFO
		echo "gname=$3">>$INFO
		vsingle_protect "$2" "$3"
		exit 0
	fi


	if [ "x$1" == "xvdomain" ] ; then
		if [ "x$2" == "x" ] ; then
			err "vdomain protect,need view arg"	
		fi
		
		if [ "x$3" == "x" ] ; then
			err "vdomain protect,need domainname arg"
		fi
			
		echo "gmode=vdomain" >$INFO
		echo "gview=$2" >> $INFO
		echo "gname=$3">>$INFO
		vdomain_protect "$2" "$3"
		exit 0
	fi
	
	
	if [ "x$1" == "xvall" ] ; then
		if [ "x$2" == "x" ] ; then
			err "vdomain protect,need view arg"   
		fi

		echo "gmode=vall" >$INFO
		echo "gview=$2" >> $INFO
		vall_protect "$2"
		exit 0
	fi


	if [ "x$1" == "xstop" ] ; then
		protect_end
		exit 0
	fi
	
	echo "usage: sh protectMgr.sh save"
	echo "usage: sh protectMgr.sh all"
	echo "usage: sh protectMgr.sh vall viewname"
	echo "usage: sh protectMgr.sh single domainname"
	echo "usage: sh protectMgr.sh vsingle viewname domainname"
	echo "usage: sh protectMgr.sh domain domain"
	echo "usage: sh protectMgr.sh vdomain viewname domain"
	
	
}

run $@

