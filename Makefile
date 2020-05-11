CC     = cc
CFLAGS = -Wall -O2 -Wextra
prefix = /usr/local

forwarp:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) forwarp.c -o forwarp

install: forwarp
	mkdir -p $(DESTDIR)$(prefix)/bin
	mv -f forwarp $(DESTDIR)$(prefix)/bin

uninstall:
	rm -f $(DESTDIR)$(prefix)/bin/forwarp

clean:
	rm -f forwarp

.PHONY: forwarp install uninstall clean
