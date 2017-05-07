OBJS=dns_parse.o miscutil.o dns.o hashmap.o response_maker.o query_records.o

.PHONY: all clean debug

default: all

debug: DFLAGS=-g -O0
debug: clean all

%.o: %.c
	$(CC) -c -o $@ $< -I. -Wall -Werror -pedantic -ansi $(DFLAGS)

all: $(OBJS)
	$(CC) $^ -o dns

clean:
	rm -rf $(OBJS) dns

