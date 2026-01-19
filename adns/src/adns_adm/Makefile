PROG = adns_adm
PROG_OBJ = libadns.o adns_adm.o

LIB = -lpopt

C_FLAGS += -Wall -Wextra -ggdb3 -O3
C_FLAGS += -I$(ADNS_TRUNK)/src/libadns
C_FLAGS += -I$(ADNS_TRUNK)/src/adns
C_FLAGS += -I$(ADNS_TRUNK)/include/common
C_FLAGS += -I$(RTE_SDK)/$(RTE_TARGET)/include

all = $(PROG)

.c.o:
	@gcc -c $< $(C_FLAGS) $(EXTRA_CFLAGS)
	@echo "  CC $<"

$(PROG):$(PROG_OBJ)
	@gcc -o $(PROG) $(PROG_OBJ) $(C_FLAGS) $(EXTRA_CFLAGS) $(LIB)
	@echo "  CC $<"

clean:
	@rm -rf *.o
	@rm -f $(PROG)

install:$(PROG)
	@[ -d ../../target/bin ] || mkdir -p ../../target/bin
	@cp -f $(PROG) ../../target/bin
	@touch ../../target/var/log/adns_adm.log
	@chmod 666 ../../target/var/log/adns_adm.log

configure:

