DIRS = adns_counter adns_rcode adns_show adns_stats adns_utili

all:
	for i in $(DIRS); do make -C $$i; cp $$i/*.so ./; done
	for i in $(DIRS); do make -C $$i; cp $$i/*.conf ./; done

clean:
	for i in $(DIRS); do cd $$i;make clean; cd ..; done

install:
	for i in $(DIRS); do make -C $$i install; done

uninstall:
	for i in $(DIRS); do make -C $$i uninstall; done



