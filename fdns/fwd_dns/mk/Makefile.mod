
include $(LDNS_TRUNK)/mk/Makefile.config
include $(LDNS_TRUNK)/mk/Makefile.include

C_FLAGS += $(INCLUDE)

EXTRA_CFLAGS += $(C_FLAGS)

KDIR = $(__KERNEL_DIR__)
PWD := $(shell pwd)

$(MOD)-objs := $(MOD_OBJ)
obj-m   := $(MOD).o

default:
	$(MAKE) -C $(KDIR) M=$(PWD)  modules
	@cp -f $(MOD).ko $(LDNS_TRUNK)/target/kmod/

clean:
	$(RM) .*.cmd *.mod.c *.o *.ko* -r .tmp* *~
	$(RM) -f Module.symvers modules.order Module.markers

install:
	make
	cp -f $(MOD).ko $(LDNS_TRUNK)/target/kmod/

configure:
	
