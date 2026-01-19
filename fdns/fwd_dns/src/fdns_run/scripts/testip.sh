vEth0=192.168.0.130
vEth1=192.168.1.130

vEth0_ip=$vEth0/30
vEth1_ip=$vEth1/30


ifconfig vEth0 up
ip addr add $vEth0_ip dev vEth0

ifconfig vEth1 up
ip addr add $vEth1_ip dev vEth1

sleep 5

service zebra restart
service ospfd restart
