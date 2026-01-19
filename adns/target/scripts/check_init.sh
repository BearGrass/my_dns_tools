#!/bin/bash
MAX_TRIAL=100 # 100 * 3s = 5mins
inter=3

# 1. check if adns is running
count=`ps -ef | grep "/home/adns/bin/adns" | grep -v "grep" | wc -l`
if [ $count -eq 0 ]; then
    echo "== ADNS is does not running =="
    exit 1
fi

# 2. check if adns is initializing...., timeout: inter-3s, dead-300s
echo "== ADNS is initiating =="
for try in $(seq 1 $MAX_TRIAL)
do
    /home/adns/bin/adns_adm -s | grep -q "Adns init loading"
    (( $? != 0 )) && echo -n "." && sleep $inter || break
done

if [ $try -eq $MAX_TRIAL ]; then
    echo "== ADNS init too long, need checking. =="
    exit 1
fi


echo -e "\n== ADNS initiation is done ==\n\n"
exit 0
