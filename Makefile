
CFLAGS=-Wall -g -O0 -ansi -pedantic

SRCS=$(wildcard *.c)

all: sheerdns sheerdnshash sheerdns.ps

OBJECTS=$(SRCS:.c=.o)

sheerdns: $(OBJECTS)
	gcc -o sheerdns $(OBJECTS)

sheerdnshash: hash.c
	gcc $(CFLAGS) -o sheerdnshash hash.c -DSTANDALONE -Wall

.c.o: $(SRCS)
	gcc $(CFLAGS) -c $<

clean:
	rm -f sheerdns sheerdnshash *.o

distclean: clean
	rm -f core *~ sheerdns.ps *.diss

sheerdns.ps:
	groff -Tps -mandoc sheerdns.8 > sheerdns.ps

install: all
	install sheerdnshash sheerdns /usr/sbin/
	install sheerdns.8 /usr/share/man/man8/
	install sheerdns.8 /usr/man/man8/

