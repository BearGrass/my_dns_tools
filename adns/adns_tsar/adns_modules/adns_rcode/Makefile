CFLAGS = -Wall -fPIC --shared -g -O2
CC = gcc
INCLUDE_DIR = ../../devel
LINK = $(CC) -I$(INCLUDE_DIR) $(CFLAGS)


OBJS =  mod_adns_rcode.so

all: $(OBJS)

$(OBJS): %.so: %.c
	$(LINK) $< -o $@
clean:
	rm -f *.so;
install:
	mkdir -p /etc/adns_tsar/conf.d/
	cp ./mod_adns_rcode.so /usr/local/adns_tsar/modules/
	cp ./mod_adns_rcode.conf /etc/adns_tsar/conf.d/adns_rcode.conf
uninstall:
	rm /usr/local/adns_tsar/modules/mod_adns_rcode.so
	rm /etc/adns_tsar/conf.d/adns_rcode.conf
