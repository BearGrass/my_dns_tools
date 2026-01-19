TEST = test_asmega_adm
TEST_OBJ = test.o lib_asmega_adm_test.o

TEST_FLAGS = -L$(DNS_TRUNK)/src/asmega_adm 
TEST_LIB = -lasmega_adm

C_FLAGS += -Wall -Wextra -ggdb3 -O2
C_FLAGS += -I$(DNS_TRUNK)/src/include

all:$(TEST)

.c.o:
	gcc -c $< $(C_FLAGS)
	
test.o:test.c
	gcc -c  $< -o $@ $(C_FLAGS)
	
lib_asmega_adm_test.o:lib_asmega_adm_test.c
	gcc -c  $< -o $@ $(C_FLAGS)
	
$(TEST):$(TEST_OBJ)
	gcc -o $(TEST) $(TEST_OBJ) $(C_FLAGS) $(TEST_FLAGS) $(TEST_LIB)
	
clean:
	@rm -rf *.o
	@rm -f $(TEST)

install:
	@echo "INSTALL-TEST $(TEST)"

