#!/bin/bash

# Author: Andy Chen <sanjie.cyg@taobao.com>
# adns deploy script

ADNS_PATH="/home/adns"
LINUX_DRV="ixgbe"
LINUX_DRV_40G="i40e"

# Creates hugepage filesystem.
create_mnt_huge()
{
	echo "Creating /mnt/huge and mounting as hugetlbfs"
	sudo mkdir -p /mnt/huge

	grep -s '/mnt/huge' /proc/mounts > /dev/null
	if [ $? -ne 0 ] ; then
		sudo mount -t hugetlbfs nodev /mnt/huge
	fi
}

# Removes hugepage filesystem.
remove_mnt_huge()
{
	echo "Unmounting /mnt/huge and removing directory"
	grep -s '/mnt/huge' /proc/mounts > /dev/null
	if [ $? -eq 0 ] ; then
		sudo umount /mnt/huge
	fi

	if [ -d /mnt/huge ] ; then
		sudo rm -R /mnt/huge
	fi
}

# Removes all reserved hugepages.
clear_huge_pages()
{
	remove_mnt_huge
}

# Creates hugepages on specific NUMA nodes.
set_numa_pages()
{
	clear_huge_pages
    create_mnt_huge
}

# init hugepages
init_hugepage()
{
	set_numa_pages
}

# hugepages cleanup
remove_hugepage()
{
	clear_huge_pages
}

# Unloads igb_uio.ko.
remove_igb_uio_module()
{
	echo "Unloading any existing DPDK UIO module"
	/sbin/lsmod | grep -s igb_uio > /dev/null
	if [ $? -eq 0 ] ; then
		sudo /sbin/rmmod igb_uio
	fi
}

# Loads new igb_uio.ko (and uio module if needed).
load_igb_uio_module()
{
	if [ ! -f $ADNS_PATH/kmod/igb_uio.ko ];then
		echo "Module igb_uio.ko does not exist!"
		exit	
	fi

	#remove_igb_uio_module

	/sbin/lsmod | grep -s -w uio > /dev/null
	if [ $? -ne 0 ] ; then
		if [ -f /lib/modules/$(uname -r)/kernel/drivers/uio/uio.ko ] ; then
			echo "Loading uio module"
			sudo /sbin/modprobe uio
		fi
	fi

	# UIO may be compiled into kernel, so it may not be an error if it can't
	# be loaded.

    /sbin/lsmod | grep -s igb_uio > /dev/null
	if [ $? == 0 ] ; then
		echo "Module igb_uio.ko already exists! Do nothing!"
		return
	fi
	echo "Loading DPDK UIO module"
	sudo /sbin/insmod $ADNS_PATH/kmod/igb_uio.ko
	if [ $? -ne 0 ] ; then
		echo "Failed to load igb_uio.ko."
		exit
	fi
}

# Unloads the rte_kni.ko module.
remove_kni_module()
{
	echo "Unloading any existing DPDK KNI module"
	/sbin/lsmod | grep -s rte_kni > /dev/null
	if [ $? -eq 0 ] ; then
		sudo /sbin/rmmod rte_kni
	fi
}

# Loads the rte_kni.ko module.
load_kni_module()
{
    # Check that the KNI module is already built.
	if [ ! -f $ADNS_PATH/kmod/rte_kni.ko ];then
		echo "Module rte_kni.ko does not exist!"
		exit
	fi

    # Unload existing version if present.
	#remove_kni_module
	
    /sbin/lsmod | grep -s i2c_core > /dev/null
    if [ $? -ne 0 ] ; then
        if [ -f /lib/modules/$(uname -r)/kernel/drivers/i2c/i2c-core.ko ] ; then
            echo "Loading i2c_core module"
            sudo /sbin/modprobe i2c_core
        fi
    fi

	/sbin/lsmod | grep -s rte_kni > /dev/null
	if [ $? == 0 ] ; then
		echo "Module rte_kni.ko already exists! Do nothing!"
		return
	fi
    # Now try load the KNI module.
	echo "Loading DPDK KNI module"
	sudo /sbin/insmod $ADNS_PATH/kmod/rte_kni.ko kthread_mode=multiple
	if [ $? -ne 0 ] ; then
		echo "Failed to load rte_kni.ko."
		exit
	fi
}

# load all needed modules
load_modules()
{
	load_igb_uio_module
	load_kni_module
}

# remove all non-needed modules
remove_modules()
{
	remove_kni_module
	remove_igb_uio_module
}

# Uses dpdk_nic_bind.py to move devices to work with igb_uio
bind_nics()
{
	shift
	nics=$@
     
   
	if  /sbin/lsmod  | grep -q igb_uio ; then 
		if $ADNS_PATH/scripts/dpdk_nic_bind.py --status | grep -q -i "drv=igb_uio" ; then
			echo "Nics already bound, try reinit"
			exit
		fi
		if [[ $nics == "" ]]; then
			#nics=`$ADNS_PATH/scripts/dpdk_nic_bind.py --status | grep -i $nic_type | awk -F 'if=' '{print $2}' | awk '{print $1}' | paste -s`
			for nic in t1 t2; do ifdown ${nic}; done
			#nics=$($ADNS_PATH/scripts/dpdk_nic_bind.py --status | grep -i $nic_type | awk '{print $1}' | paste -s)
			echo "Will bind NICs: t1 t2 to *igb_uio* driver."
			$ADNS_PATH/scripts/dpdk_nic_bind.py --bind=igb_uio t1 t2 && echo "OK"
		else
            for nic in $@; do ifdown ${nic}; done
			echo "Will bind NICs: $@ from *$LINUX_DRV* to *igb_uio* driver."
			$ADNS_PATH/scripts/dpdk_nic_bind.py --bind=igb_uio $@ && echo "OK"
		fi

	else 
		echo "# Please load the 'igb_uio' kernel module before bind nics."
	fi
}

# Uses dpdk_nic_bind.py to move devices to work with kernel drivers(ixgbe) again
unbind_nics()
{
	if  /sbin/lsmod  | grep -q igb_uio ; then 
        if $ADNS_PATH/scripts/dpdk_nic_bind.py --status | grep -i "drv=igb_uio" | grep -q XL710 ; then
            target_drv=$LINUX_DRV_40G
        else
            target_drv=$LINUX_DRV
        fi
		bind_nics=$($ADNS_PATH/scripts/dpdk_nic_bind.py --status | grep -i "drv=igb_uio" | awk '{print $1}' | paste -s)
		echo "Will unbind NICs: $bind_nics from *igb_uio* to *$target_drv* driver."
		#/sbin/modprobe -r $LINUX_DRV
		#/sbin/modprobe $LINUX_DRV
		$ADNS_PATH/scripts/dpdk_nic_bind.py -b $target_drv $bind_nics && echo "OK"
	else
		echo "# Does not needed to unbind nics as igb_uio modules not loaded."
	fi
}

# set logrotate config
set_logrotate()
{
	# execute logrotate every 5 minites, default is everyday
	if ! grep -Fq '*/5  *  *  *  * root /etc/cron.daily/logrotate' /etc/crontab
	then
		echo '*/5  *  *  *  * root /etc/cron.daily/logrotate # ADNS generate log very fast, so logrotate it every 5 minutes.' >> /etc/crontab
	fi

	# get the largest disk size
	largest_disk=`df | awk '{print $2}' | sort -g | tail -n 1`

	if [ $largest_disk -ge 3000000000000 ]
	then
		sudo ln -sf /home/adns/var/log/adns_query.log /disk1/adns_log/adns_query.log
		sudo ln -sf /home/adns/etc/adns_logrotate_3T.conf /etc/logrotate.d/adns.conf
		[[ -d /disk1/adns_log/ ]] || sudo mkdir /disk1/adns_log/
	else
		sudo ln -sf /home/adns/etc/adns_logrotate.conf /etc/logrotate.d/adns.conf
	fi
}

# remove logrotate config
remove_logrotate()
{
	# execute logrotate every 5 minites, default is everyday
	if grep -Fq '*/5  *  *  *  * root /etc/cron.daily/logrotate' /etc/crontab
	then
		sudo sed -i '/\*\/5\ \ \*\ \ \*\ \ \*\ \ \*\ root\ \/etc\/cron.daily\/logrotate/d' /etc/crontab
	fi

	# get the largest disk size
	largest_disk=`df | awk '{print $2}' | sort -g | tail -n 1`

	if [ $largest_disk -ge 3000000000000 ]
	then
		sudo rm -f /disk1/adns_log/adns_query.log
		sudo rm -f /etc/logrotate.d/adns.conf
	else
		sudo rm -f /etc/logrotate.d/adns.conf
	fi
}

# adns deploy init
adns_deploy_init()
{
	echo "*** Start init adns environment... ***"

	# load modules
	load_modules

	# init hugepage
	init_hugepage

	# bind 82599 or XL710 nics to igb_uio driver
	bind_nics $@

	echo "*** Init adns environment done! ***"
}

# adns deploy init
adns_deploy_init_mlx()
{
	echo "*** Start init adns environment... ***"
	shift
	nics=$@

	# load modules
	load_modules

	# init hugepage
	init_hugepage

	if [[ $nics == "" ]]; then
		for nic in t1 t2; do ifdown ${nic}; done
	else
            for nic in $@; do ifdown ${nic}; done
	fi

	echo "*** Init adns environment done! ***"
}

# adns deploy cleanup
# adns deploy cleanup
adns_deploy_clean()
{
	echo "*** Start clear adns environment... ***"

	# remove logrotate config
	remove_logrotate

	# unbind 82599 or XL710 nics
	unbind_nics

	# remove hugepage
	remove_hugepage

	# remove modules
	remove_modules

	echo "*** Clear adns environment done ***"
}

case "$1" in
	init)
	adns_deploy_init $@
	;;
	initmlx)
	adns_deploy_init_mlx $@
	;;
	clean)
	adns_deploy_clean
	;;
	reinit)
	adns_deploy_clean
	adns_deploy_init $@
	;;
	reinitmlx)
	adns_deploy_clean
	adns_deploy_init_mlx $@
	;;
	*)
	echo "Usage: $0 {init|clean|reinit|initmlx|reinitmlx}"
esac

