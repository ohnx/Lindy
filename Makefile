.PHONY: all clean

%.o: %.c
	$(CC) -c -o $@ $< -I.

all: dns_parse.o miscutil.o dns.o
	$(CC) $^ -o dns -Wall -Werror -pedantic -ansi

clean:
	rm -rf *.o dns

