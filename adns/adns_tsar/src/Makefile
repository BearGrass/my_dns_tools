CFLAGS = -g -O0 -Wall
CC = gcc
INCLUDE_DIR = ../include


%.o: %.c
	$(CC) -o $@ -c -I$(INCLUDE_DIR) $(CFLAGS) $<

all: adns_tsar

adns_tsar: config.o debug.o framework.o adns_tsar.o output_file.o output_print.o output_db.o output_nagios.o common.o
	$(CC) config.o debug.o framework.o adns_tsar.o output_file.o output_print.o output_db.o output_nagios.o common.o -o adns_tsar -I$(INCLUDE_DIR) -g -Wall -ldl -rdynamic

clean:
	rm -rf *.o adns_tsar
