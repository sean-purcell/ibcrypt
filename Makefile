CC=gcc
BUILDDIR=bin
CFLAGS=-Wall -std=gnu99 -O3
LINKFLAGS=-flto

LIBINC=-I/usr/local/include

DIRS=test cipher hash bn misc include
BUILDDIRS=$(patsubst %,$(BUILDDIR)/%,$(DIRS))

SOURCES:= 
TESTSOURCES:= 

INCLUDEDIR=include
HEADERDIR=$(BUILDDIR)/include/ibcrypt

LIBINC+=-I$(HEADERDIR)

include $(patsubst %,%/inc.mk,$(DIRS))

OBJECTS:=$(patsubst %.c,$(BUILDDIR)/%.o,$(SOURCES))
TESTSOURCES+=$(SOURCES)
TESTOBJECTS:=$(patsubst %.c,$(BUILDDIR)/%.o,$(TESTSOURCES))

BUILDHEADERS:=$(patsubst include/%.h,$(HEADERDIR)/%.h,$(HEADERS))

.PHONY: libheaders lib clean install

lib: $(BUILDDIR) $(BUILDHEADERS) $(OBJECTS)
	ar -rs bin/libibcrypt.a $(OBJECTS)

$(BUILDDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $(LIBINC) $< -o $@

$(HEADERDIR)/%.h: include/%.h
	cp $< $@

$(BUILDDIR):
	@mkdir -p $(BUILDDIR) $(BUILDDIRS) $(HEADERDIR)

install:
	cp bin/libibcrypt.a /usr/local/lib/
	cp -r bin/include/ibcrypt /usr/local/include/

clean:
	rm -rf $(BUILDDIR)

