# DHCP discover-only client
# This program checks for the presence of a DHCP server on the network,
# and prints the information it receives from the server.
#
# (c) 2024 Dyne.org - Licensed under the GPLv3 - see license for details
#
# Authors: Daniele Lacamera and Denis Roio
#

CC ?= gcc

ifdef RELEASE
CFLAGS := -O2 -fstack-protector-all -D_FORTIFY_SOURCE=2 -fno-strict-overflow
else
CFLAGS := -Wall -Wextra -Werror -Og -ggdb -DDEBUG=1
LDFLAGS :=
endif

ifdef ASAN
	CFLAGS  += -fno-omit-frame-pointer -fsanitize=address
	LDFLAGS := -fsanitize=address
endif

dhcp-spy: dhcp-spy.o
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o dhcp-spy

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@
#	-DVERSION=\"${VERSION}\" \
#	-DCURRENT_YEAR=\"${CURRENT_YEAR}\"
