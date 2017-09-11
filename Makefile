include Makedefs

prefix=$(DESTDIR)/usr
bindir=$(prefix)/bin

BINS=usbreplay
SCRIPTS=

OBJECTS = $(patsubst %.c,%.o,$(shell find . -name "*.c" -not -path "./test/*" -not -path "./lib/*"))
OBJECTS:=$(filter-out test/*,$(OBJECTS))

DIRS = lib/gimxpoll lib/gimxprio lib/gimxtimer lib/gimxusb

BUILDDIRS = $(DIRS:%=build-%)
INSTALLDIRS = $(DIRS:%=install-%)
CLEANDIRS = $(DIRS:%=clean-%)
UNINSTALLDIRS = $(DIRS:%=uninstall-%)

ifeq ($(OS),Windows_NT)
build-gimxusb: build-gimxtimer build-gimxpoll
endif

all: $(BUILDDIRS) $(BINS)

$(DIRS): $(BUILDDIRS)

$(BUILDDIRS):
	$(MAKE) -C $(@:build-%=%)

usbreplay: $(OBJECTS)

clean: $(CLEANDIRS)
	$(RM) $(OBJECTS) $(BINS)

$(CLEANDIRS): 
	$(MAKE) -C $(@:clean-%=%) clean

install: $(INSTALLDIRS) all
	mkdir -p $(prefix)
	mkdir -p $(bindir)
	for i in $(BINS); do cp $$i $(bindir)/; done
	for i in $(SCRIPTS); do cp $$i $(bindir)/; done

$(INSTALLDIRS):
	$(MAKE) -C $(@:install-%=%) install

uninstall: $(UNINSTALLDIRS)
	-for i in $(SCRIPTS); do $(RM) $(bindir)/$$i; done
	-for i in $(BINS); do $(RM) $(bindir)/$$i; done
	-$(RM) $(bindir)
	-$(RM) $(prefix)

$(UNINSTALLDIRS):
	$(MAKE) -C $(@:uninstall-%=%) uninstall

really-clean: clean uninstall

.PHONY: subdirs $(DIRS)
.PHONY: subdirs $(BUILDDIRS)
.PHONY: subdirs $(CLEANDIRS)
.PHONY: all clean
