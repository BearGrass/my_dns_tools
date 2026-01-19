gap=10
q1=`bin/fwdctl  -s 127.0.0.1 -p 6666 rstats|grep '|' |tail -n 1|awk '{print $1}'`;
echo $q1
sleep $gap;
q2=`bin/fwdctl  -s 127.0.0.1 -p 6666 rstats|grep '|' |tail -n 1|awk '{print $1}'`;
echo $q2
echo -n "($q2-$q1)/$gap = "
if [ $q1 -eq $q2 ] ; then
	echo 0
else
	echo "($q2-$q1)/$gap "|bc
fi
