CC=gcc
#CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=c99
CFLAGS=-Wall -Wstrict-prototypes -Werror -fPIC -std=gnu99 -g

LD_SONAME=-Wl,-soname,libapam.so.2
LIBRARY=libapam.so.2.0
LINKS=libapam.so.2 libapam.so

DESTDIR=/
PREFIX=$(DESTDIR)/usr
LIBDIR=$(PREFIX)/lib
BUILD=.libs

default: build passwd-test
build: apam

apam_build_dir:
	[ -d $(BUILD) ] || mkdir $(BUILD)

passwd-test:
	$(CC) $(CFLAGS) passwd-util.c -o $(BUILD)/passwd-test

passwd-util:
	$(CC) $(CFLAGS) -DNDEBUG -c passwd-util.c -o $(BUILD)/passwd-util.o

apam-passwd:
	$(CC) $(CFLAGS) -DNDEBUG -c apam-passwd.c -o $(BUILD)/apam-passwd.o

apam-group:
	$(CC) $(CFLAGS) -DNDEBUG -c apam-group.c -o $(BUILD)/apam-group.o

apam-shadow:
	$(CC) $(CFLAGS) -DNDEBUG -c apam-shadow.c -o $(BUILD)/apam-shadow.o

apam_services: apam-passwd apam-group apam-shadow passwd-util

apam: apam_build_dir apam_services
	$(CC) -shared $(LD_SONAME) -o $(BUILD)/$(LIBRARY) \
		$(BUILD)/apam-passwd.o \
		$(BUILD)/apam-group.o \
		$(BUILD)/apam-shadow.o

clean:
	rm -rf $(BUILD)

install:
	[ -d $(LIBDIR) ] || install -d $(LIBDIR)
	install $(BUILD)/$(LIBRARY) $(LIBDIR)
	cd $(LIBDIR); for link in $(LINKS); do ln -sf $(LIBRARY) $$link ; done

.PHONY: clean install apam_build_dir apam
