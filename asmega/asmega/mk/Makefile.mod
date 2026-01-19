include $(DNS_TRUNK)/mk/Makefile.config
include $(DNS_TRUNK)/mk/Makefile.include

C_FLAGS += $(INCLUDE) -Wall

EXTRA_CFLAGS += $(C_FLAGS)
EXTRA_CFLAGS += -g -O0


KDIR = $(__KERNEL_DIR__)
PWD := $(shell pwd)

$(MOD)-objs := $(MOD_OBJ)
obj-m   := $(MOD).o

default:
	$(MAKE) -C $(KDIR) M=$(PWD)  modules
clean:
	$(RM) .*.cmd *.mod.c *.o *.ko* -r .tmp*
	$(RM) -f Module.symvers modules.order Module.markers
install:
	make
	@[ -d $(DNS_TRUNK)/target/kmod ] || mkdir -p $(DNS_TRUNK)/target/kmod
	cp $(MOD).ko $(DNS_TRUNK)/target/kmod/

configure:
	
