CC=gcc
#CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=c99
CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=gnu99 -g

LD_SONAME=-Wl,-soname,libnss_http.so.2
LIBRARY=libnss_http.so.2.0
LINKS=libnss_http.so.2 libnss_http.so

DESTDIR=/
PREFIX=$(DESTDIR)/usr
LIBDIR=$(PREFIX)/lib
BUILD=.libs

default: build passwd-test
build: nss_http

nss_http_build_dir:
	[ -d $(BUILD) ] || mkdir $(BUILD)

passwd-test:
	$(CC) $(CFLAGS) passwd-util.c -o $(BUILD)/passwd-test

passwd-util:
	$(CC) $(CFLAGS) -c passwd-util.c -o $(BUILD)/passwd-util.o

nss_http-passwd:
	$(CC) $(CFLAGS) -c nss_http-passwd.c -o $(BUILD)/nss_http-passwd.o

nss_http-group:
	$(CC) $(CFLAGS) -c nss_http-group.c -o $(BUILD)/nss_http-group.o

nss_http-shadow:
	$(CC) $(CFLAGS) -c nss_http-shadow.c -o $(BUILD)/nss_http-shadow.o

nss_http_services: nss_http-passwd nss_http-group nss_http-shadow passwd-util

nss_http: nss_http_build_dir nss_http_services
	$(CC) -shared $(LD_SONAME) -o $(BUILD)/$(LIBRARY) \
		$(BUILD)/nss_http.o \
		$(BUILD)/nss_http-passwd.o \
		$(BUILD)/nss_http-group.o \
		$(BUILD)/nss_http-shadow.o \
        -lcurl -ljansson

clean:
	rm -rf $(BUILD)

install:
	[ -d $(LIBDIR) ] || install -d $(LIBDIR)
	install $(BUILD)/$(LIBRARY) $(LIBDIR)
	cd $(LIBDIR); for link in $(LINKS); do ln -sf $(LIBRARY) $$link ; done

.PHONY: clean install nss_http_build_dir nss_http
