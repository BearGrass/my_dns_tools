#!/bin/sh
#****************************************************************#
# ScriptName: gcov_dns.sh
# Author: hejun.hj@alibaba-inc.com
# Create Date: 2015-05-07 11:33
# Modify Author: $SHTERM_REAL_USER@alibaba-inc.com
# Modify Date: 2015-05-21 11:19
# Function: 
#***************************************************************#

lcov --capture --directory ../src/adns/build/ --output-file dns_test_1.info --test-name test_dns
lcov --capture --directory ../src/libadns/build/ --output-file dns_test_2.info --test-name test_dns
lcov --capture --directory ../src/common/build/ --output-file dns_test_3.info --test-name test_dns
genhtml dns_test_1.info dns_test_2.info dns_test_3.info --output-directory gcov_out/ --title "DNS Test" --show-details --legend



