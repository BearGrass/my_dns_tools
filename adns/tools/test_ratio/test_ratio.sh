#!/bin/bash
domain=www1.myexamplezone1.org.
#domain=www.hejun.com.
ip1=1.1.1.1
ip2=1.1.1.2
ip3=1.1.1.3
n1=0
n2=0
n3=0
o=0
for i in $(seq $1)
do
	ip=$(dig @192.168.6.6 "$domain" +short);
	if [ "$ip" = "$ip1" ]
	then
		let n1=$(($n1+1));
	elif [ "$ip" = "$ip2" ]
	then
		let n2=$(($n2+1));
	elif [ "$ip" = "$ip3" ]
	then
		let n3=$(($n3+1));
	else 
		let o=$(($o+1));
	fi
done

echo  "$ip1 = $n1"
echo  "$ip2 = $n2"
echo  "$ip3 = $n3"
echo  "other = $o"

