CC=gcc
#CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=c99
CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=gnu99 -g

LD_SONAME=-Wl,-soname,libapam.so.2
LIBRARY=libnss_apam.so.2.0
LINKS=libnss_apam.so.2 libnss_apam.so

DESTDIR=/
PREFIX=$(DESTDIR)/usr
LIBDIR=$(PREFIX)/lib
BUILD=.libs

default: build passwd-test
build: nss_apam

nss_apam_build_dir:
	[ -d $(BUILD) ] || mkdir $(BUILD)

passwd-test:
	$(CC) $(CFLAGS) passwd-util.c -o $(BUILD)/passwd-test

passwd-util:
	$(CC) $(CFLAGS) -DNDEBUG -c passwd-util.c -o $(BUILD)/passwd-util.o

nss_apam-passwd:
	$(CC) $(CFLAGS) -DNDEBUG -c nss_apam-passwd.c -o $(BUILD)/nss_apam-passwd.o

nss_apam-group:
	$(CC) $(CFLAGS) -DNDEBUG -c nss_apam-group.c -o $(BUILD)/nss_apam-group.o

nss_apam-shadow:
	$(CC) $(CFLAGS) -DNDEBUG -c nss_apam-shadow.c -o $(BUILD)/nss_apam-shadow.o

nss_apam_services: nss_apam-passwd nss_apam-group nss_apam-shadow passwd-util

nss_apam: nss_apam_build_dir nss_apam_services
	$(CC) -shared $(LD_SONAME) -o $(BUILD)/$(LIBRARY) \
		$(BUILD)/nss_apam-passwd.o \
		$(BUILD)/nss_apam-group.o \
		$(BUILD)/nss_apam-shadow.o

clean:
	rm -rf $(BUILD)

install:
	[ -d $(LIBDIR) ] || install -d $(LIBDIR)
	install $(BUILD)/$(LIBRARY) $(LIBDIR)
	cd $(LIBDIR); for link in $(LINKS); do ln -sf $(LIBRARY) $$link ; done

.PHONY: clean install nss_apam_build_dir nss_apam
