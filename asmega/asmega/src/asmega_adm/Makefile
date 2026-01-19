PROG = asmega_adm
PROG_OBJ = asmega_adm.o
SO = libasmega_adm.so
SO_OBJ = lib_asmega_adm.o
TEST = test_asmega_adm
TEST_OBJ = lib_asmega_adm_test.o

TEST_FLAGS = -L. 
TEST_LIB = -lasmega_adm

SO_FLAGS = -fPIC -shared
SO_LIB =

C_FLAGS += -Wall -Wextra -ggdb3 -O2
C_FLAGS += -I$(DNS_TRUNK)/src/include

all:$(PROG) $(SO)

.c.o:
	gcc -c $< $(C_FLAGS)
	
$(PROG):$(PROG_OBJ)
	gcc -o $(PROG) $(PROG_OBJ) $(C_FLAGS) $(LIB)
	
lib_asmega_adm.o:lib_asmega_adm.c
	gcc -fpic -c $< -o $@ $(C_FLAGS)
	
$(SO):$(SO_OBJ)
	gcc -o $(SO) $(SO_OBJ) $(SO_FLAGS) $(C_FLAGS) $(SO_LIB)
	
clean:
	@rm -rf *.o
	@rm -rf *.so
	@rm -f $(PROG)
	@rm -f $(TEST)
	@rm -rf $(DNS_TRUNK)/target/lib

install:
	@echo "INSTALL-APP $(PROG)"
	@[ -d $(DNS_TRUNK)/target/bin ] || mkdir -p $(DNS_TRUNK)/target/bin
	@cp $(PROG) $(DNS_TRUNK)/target/bin/
	@echo "INSTALL-LIB $(SO)"
	@[ -d $(DNS_TRUNK)/target/lib ] || mkdir -p $(DNS_TRUNK)/target/lib
	@cp $(SO) $(DNS_TRUNK)/target/lib/
