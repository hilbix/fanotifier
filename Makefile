#

TARG=fanotifier
CFLAGS=-Wall -O3 -g
LDLIBS=-lpthread
PREFIX=$(HOME)

.PHONY: all install clean distclean

all:	$(TARG)

gdb:	all
	sudo gdb -ex run --args './$(TARG)' -0

install:
	cp '$(TARG)' '$(PREFIX)/bin/$(TARG)'
	strip -s '$(PREFIX)/bin/$(TARG)'

clean:	distclean

distclean:
	rm -f '$(TARG)'

