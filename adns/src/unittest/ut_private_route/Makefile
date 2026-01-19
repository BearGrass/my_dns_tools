PROJECT               = private_route_unittest
UNITTEST_SRC          = ./*.cc
C_SRC                 = ../../libadns/private_route.c
C_INCLUDE			  = -I../../libadns -I../../../include/common -I$(DPDK_INC_PATH)
FLAGS                 = -rvf
DELETE                = rm
CPP					  = g++
GCC					  = gcc
CP                    = cp
GTESTINCLUDE          = -I../include
GTESTLIB              = -L../
COVERAGEOPT           = -fprofile-arcs -ftest-coverage

all:
	$(DELETE) $(FLAGS)  output*
	$(GCC) -g -c -DUNIT_TEST $(C_SRC) $(C_INCLUDE) -include $(DPDK_INC_PATH)/rte_config.h
	$(CPP) -g $(GTESTINCLUDE) -c $(UNITTEST_SRC) $(C_INCLUDE) -include $(DPDK_INC_PATH)/rte_config.h 
	$(GCC) -g -o output ./*.o ../../common/build/libadns_common.a ../../libadns/build/libadns_dns.a ../libdpdk/libdpdk.a -lstdc++ $(GTESTINCLUDE) $(GTESTLIB) $(C_INCLUDE) -lgtest -lpthread -lrt -ldl

clean:
	$(DELETE) $(FLAGS)  output
	$(DELETE) $(FLAGS)  ./*.o
	$(DELETE) $(FLAGS)  sur.txt ./*.gcno ./*.gcda
