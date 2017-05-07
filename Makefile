OBJS=dns_parse.o miscutil.o dns.o hashmap.o response_maker.o

.PHONY: all clean

%.o: %.c
	$(CC) -c -o $@ $< -I. -Wall -Werror -pedantic -ansi

all: $(OBJS)
	$(CC) $^ -o dns -Wall -Werror -pedantic -ansi

clean:
	rm -rf $(OBJS) dns

