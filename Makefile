# Common makefile -- loads make rules for each platform

### FIXME: ZT_DEBUG=1 is currently required.  Otherwise the build hangs!.
ZT_DEBUG=1

OSTYPE?=$(shell uname -s)

VERSION=0.1.4
NAME=onetierzero

dist: force
	tar --exclude .git --exclude *.tar* -czf $(NAME)-$(VERSION).tar.gz *

ifeq ($(OSTYPE),Darwin)
  include make-mac.mk
endif

ifeq ($(OSTYPE),Linux)
  include make-linux.mk
endif

ifeq ($(OSTYPE),FreeBSD)
  CC=clang
  CXX=clang++
  ZT_BUILD_PLATFORM=7
  include make-bsd.mk
endif
ifeq ($(OSTYPE),OpenBSD)
  CC=egcc
  CXX=eg++
  ZT_BUILD_PLATFORM=9
  include make-bsd.mk
endif

ifeq ($(OSTYPE),NetBSD)
  include make-netbsd.mk
endif

SYS_ROOT=/home/u/.cache/lambdanative/linux

GSC=$(SYS_ROOT)/bin/gsc

GSCFLAGS= -report -track-scheme # -debug

GSCINCL=$(SYS_ROOT)/include

LIKELY_DIR=$(HOME)/build/ln/modules/likely
MATCH_DIR=$(HOME)/build/ln/modules/akwmatch
LWIP_DIR=$(HOME)/build/ln/modules/lwip

INCLUDES+=-I. -I $(BINDINGS_DIR) -I $(GSCINCL)

BINDINGS_DIR=bindings

OT0_INCLUDES=$(BINDINGS_DIR)/ot0core.scm $(BINDINGS_DIR)/ot0core-extensions.scm
ot0.c: $(BINDINGS_DIR)/ot0.scm $(OT0_INCLUDES) $(BINDINGS_DIR)/ot0-hooks.h
	$(GSC) $(GSCFLAGS) -o $@ -c $(BINDINGS_DIR)/ot0.scm

ot0_.c: ot0.c
	$(GSC) $(GSCFLAGS) -o ot0_.c -link ot0.c

OT0_CLI_INCLUDES=$(BINDINGS_DIR)/test-environment.scm $(BINDINGS_DIR)/ot0use.scm

GSC_SYNTAX_FLAGS=-e '(load "~~/lib/match.o1")'

ot0cli.c: $(BINDINGS_DIR)/ot0cli.scm $(OT0_CLI_INCLUDES) Makefile
	$(GSC) $(GSCFLAGS) -o $@ -c $(GSC_SYNTAX_FLAGS) $(BINDINGS_DIR)/ot0cli.scm

# TODO: compute these!
OT0_GAMBITC_SOURCES=ot0.c irregex.c

OT0_OBJECTS=ot0-hooks.o ot0.o

OT0_CLI_GAMBITC_FILES=$(MATCH_DIR)/match.c $(LIKELY_DIR)/likely.gambit.c $(LWIP_DIR)/lwip.c ot0cli.c #  irregex.c

ot0cli_.c: $(OT0_CLI_GAMBITC_FILES) $(OT0_GAMBITC_SOURCES)
	$(GSC) $(GSCFLAGS) -o ot0cli_.c -link $(OT0_GAMBITC_SOURCES) $(OT0_CLI_GAMBITC_FILES)

#ot0cli.o: ot0cli.c
#	$(GSC) $(GSCFLAGS) -o $@ -obj ot0cli.scm

ot0-hooks.o: $(BINDINGS_DIR)/ot0-hooks.cpp $(BINDINGS_DIR)/ot0-hooks.h
	$(CXX) -c $(CXXFLAGS) -o $@ $(BINDINGS_DIR)/ot0-hooks.cpp

likely.gambit.o: $(LIKELY_DIR)/likely.gambit.c
	$(CC) -c $(CCFLAGS) $(INCLUDES) -o $@ $<

lwip.o: $(LWIP_DIR)/lwip.c
	$(CC) -c $(CCFLAGS) $(INCLUDES) -o $@ $<

irregex.c: $(BINDINGS_DIR)/irregex.scm
	$(GSC) $(GSCFLAGS) -o $@ -c $(GSC_SYNTAX_FLAGS) $(BINDINGS_DIR)/irregex.scm

OT0_CLI_OBJECTS=$(MATCH_DIR)/match.o likely.gambit.o lwip.o irregex.o ot0cli.o ot0cli_.o

ot0: $(OT0_CLI_OBJECTS) $(OT0_OBJECTS) #libzerotiercore.a
	$(CXX) -o ot0 -L. -L $(SYS_ROOT)/lib $(OT0_OBJECTS) $(OT0_CLI_OBJECTS) \
	 -lzerotiercore -llwipcore -lgambit -ldl -lutil

test: # Test It
test: ot0
	./ot0 -tests $(BINDINGS_DIR)/ot0-tests.scm : -exit

weg: force
	-rm $(OT0_CLI_GAMBITC_FILES) $(OT0_GAMBITC_SOURCES) $(OT0_OBJECTS) $(OT0_CLI_OBJECTS)

xclean:	# remove backupfiles (*~)
xclean: force
	rm -f `find . -type f -name "*~" -print`
force:

help:	# help on possible targets
	-@egrep "^[-A-Za-z0-9\._]+::?.*#" [Mm]akefile
