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

default: build
build: nss_apam

nss_apam_build_dir:
	[ -d $(BUILD) ] || mkdir $(BUILD)

pwdgrp-util:
	$(CC) $(CFLAGS) -DNDEBUG -c pwdgrp-util.c -o $(BUILD)/pwdgrp-util.o

nss_apam-obj:
	$(CC) $(CFLAGS) -DNDEBUG -c nss_apam.c -o $(BUILD)/nss_apam.o

nss_apam_services: nss_apam-obj pwdgrp-util

nss_apam: nss_apam_build_dir nss_apam_services links
	$(CC) -shared $(LD_SONAME) -o $(BUILD)/$(LIBRARY) \
		$(BUILD)/nss_apam.o \
        $(BUILD)/pwdgrp-util.o 

nss_apam-test: nss_apam
	$(CC) -g -o $(BUILD)/nss_apam-test nss_apam-test.c -L$(BUILD) -lnss_apam

links:
	cd $(BUILD); for link in $(LINKS); do ln -sf $(LIBRARY) $$link ; done ; cd -

test: nss_apam-test
	LD_LIBRARY_PATH=$(BUILD) $(BUILD)/nss_apam-test

clean:
	rm -rf $(BUILD)

install:
	[ -d $(LIBDIR) ] || install -d $(LIBDIR)
	install $(BUILD)/$(LIBRARY) $(LIBDIR)
	cd $(LIBDIR); for link in $(LINKS); do ln -sf $(LIBRARY) $$link ; done

.PHONY: clean install nss_apam_build_dir nss_apam test pwdgrp-util
