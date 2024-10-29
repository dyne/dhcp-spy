CC?=gcc
CFLAGS=-Wall -Wextra -Werror -O0 -g
LDFLAGS=

dhcp-spy: dhcp-spy.o
	$(CC) $(LDFLAGS) $^ -o $@

dhcp-spy.o: dhcp-spy.c
	$(CC) -c $(CFLAGS) $^ -o $@

clean:
	rm -f *.o dhcp-spy


