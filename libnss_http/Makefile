CC=gcc
#CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=c99
CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=gnu99 -g

LD_SONAME=-Wl,-soname,libnss_apam.so.2
LIBRARY=libnss_apam.so.2.0
LINKS=libnss_apam.so.2 libnss_apam.so

DESTDIR=/
PREFIX=$(DESTDIR)/usr
LIBDIR=$(PREFIX)/lib
BUILD=.libs

default: build passwd-test group-test
build: nss_apam

nss_apam_build_dir:
	[ -d $(BUILD) ] || mkdir $(BUILD)

passwd-test:
	$(CC) $(CFLAGS) passwd-util.c -o $(BUILD)/passwd-test

group-test:
	$(CC) $(CFLAGS) group-util.c -o $(BUILD)/group-test

passwd-util:
	$(CC) $(CFLAGS) -DNDEBUG -c passwd-util.c -o $(BUILD)/passwd-util.o

group-util:
	$(CC) $(CFLAGS) -DNDEBUG -c group-util.c -o $(BUILD)/group-util.o

nss_apam-passwd:
	$(CC) $(CFLAGS) -DNDEBUG -c nss_apam-passwd.c -o $(BUILD)/nss_apam-passwd.o

nss_apam-group:
	$(CC) $(CFLAGS) -DNDEBUG -c nss_apam-group.c -o $(BUILD)/nss_apam-group.o

nss_apam_services: nss_apam-passwd nss_apam-group passwd-util group-util

nss_apam: nss_apam_build_dir nss_apam_services links
	$(CC) -shared $(LD_SONAME) -o $(BUILD)/$(LIBRARY) \
		$(BUILD)/nss_apam-passwd.o \
		$(BUILD)/nss_apam-group.o \
        $(BUILD)/passwd-util.o \
        $(BUILD)/group-util.o

nss_apam-test: nss_apam
	$(CC) -o $(BUILD)/nss_apam-test nss_apam-test.c -L$(BUILD) -lnss_apam

links:
	cd $(BUILD); for link in $(LINKS); do ln -sf $(LIBRARY) $$link ; done ; cd -

test:
	LD_LIBRARY_PATH=$(BUILD) $(BUILD)/nss_apam-test

clean:
	rm -rf $(BUILD)

install:
	[ -d $(LIBDIR) ] || install -d $(LIBDIR)
	install $(BUILD)/$(LIBRARY) $(LIBDIR)
	cd $(LIBDIR); for link in $(LINKS); do ln -sf $(LIBRARY) $$link ; done

.PHONY: clean install nss_apam_build_dir nss_apam test
