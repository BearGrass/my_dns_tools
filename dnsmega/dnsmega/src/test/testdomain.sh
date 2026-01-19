#/bin/sh
HOST="dnstest05.tbc"
# 普通递归域名
ans=`dig www.alipay.com @$HOST +short`
echo $ans
# mogu.a.com 下配置了54 个 ip
ans=`dig mogu.a.com @$HOST +short`
echo $ans
# 线上最长域名
ans=`dig confreg.0000000001-0000014385-0000014383.dev01.alipay.net.a.com @$HOST +short`
echo $ans
# 泛域名
ans=`dig *.a.com @$HOST +short`
echo $ans
# 外部长域名
ans=`dig 1251008728.cdn.myqcloud.com @$HOST +short`
echo $ans
# ANY 请求
ans=`dig aliyun.com any @$HOST`
