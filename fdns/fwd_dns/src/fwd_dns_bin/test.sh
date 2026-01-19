#!/bin/sh
###
#目标：匹配指定域的所有类型
###

domain="$1"
str="$2"

####
#如果用户对这个域写了“.”结尾，则去掉这个“.” 号
####
step=`echo "$domain"|sed 's/\.$//'`  
echo "$step"
###
#把“.”替换为"\."以供正则表达式来匹配域名中的“.”号
###
step=`echo "$step"|sed 's/\./\\\./g'`
echo "$step"

###
#两种情况匹配到这个域下所有类型，以baidu.com为例
#1.  baidu.com./2 要能匹配到，即ns记录要能匹配到
#2.  www.baidu.com./1 要能匹配到，即所有以baidu.com结尾的所有域名类型都能匹配到
#而 abaidu.com./2 则不能匹配到
##
step="(.*\.|^)$step\./*"
echo "$step"

###
#跑测试
#case 1: $domain./2 must match
#case 2: www.$domain./1 must match
#case 3: a.b.$domain./5 must match
#case 4: www$domain./1 must not match
###
c1="$domain./2"
c2="www.$domain./1"
c3="a.b.$domain./5"
c4="www$domain./1"

echo "===case 1 [$c1]===="
./reg "$step" "$c1"

echo "===case 2 [$c2]===="
./reg "$step" "$c2"

echo "===case 3 [$c3]===="
./reg "$step" "$c3"

echo "===case 4 [$c4]===="
./reg "$step" "$c4"

echo "====run [$2]===="
./reg "$step" "$2"
