CC     = cc
CFLAGS = -Wall -O2 -Wextra
prefix = /usr/local
PREFIX = $(prefix)

forwarp:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) forwarp.c -o forwarp

install: forwarp
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mv -f forwarp $(DESTDIR)$(PREFIX)/bin

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/forwarp

clean:
	rm -f forwarp

.PHONY: forwarp install uninstall clean
