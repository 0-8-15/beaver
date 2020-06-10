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

GSCFLAGS= # -report -track-schemea # -debug

GSCINCL=$(SYS_ROOT)/include

LIKELY_DIR=$(HOME)/build/ln/modules/likely
MATCH_DIR=$(HOME)/build/ln/modules/akwmatch
LWIP_DIR=$(HOME)/build/ln/modules/lwip

INCLUDES+=-I. -I $(BINDINGS_DIR) -I $(GSCINCL)

BINDINGS_DIR=bindings

OT0_INCLUDES=$(BINDINGS_DIR)/ot0core.scm $(BINDINGS_DIR)/ot0core-extensions.scm $(HOME)/build/ln/modules/socks/socks.scm
ot0.c: $(BINDINGS_DIR)/ot0.scm $(OT0_INCLUDES) $(BINDINGS_DIR)/ot0-hooks.h
	$(GSC) $(GSCFLAGS) -o $@ -c $(BINDINGS_DIR)/ot0.scm

ot0_.c: ot0.c
	$(GSC) $(GSCFLAGS) -o ot0_.c -link ot0.c

OT0_CLI_INCLUDES=$(BINDINGS_DIR)/test-environment.scm $(BINDINGS_DIR)/ot0use.scm

GSC_SYNTAX_FLAGS=-e '(load "~~/lib/match.o1")'

ot0use.c: $(OT0_CLI_INCLUDES)
	$(GSC) $(GSCFLAGS) -o $@ -c $(GSC_SYNTAX_FLAGS) $(BINDINGS_DIR)/ot0use.scm

ot0cli.c: $(BINDINGS_DIR)/ot0cli.scm # Makefile
	$(GSC) $(GSCFLAGS) -o $@ -c $(GSC_SYNTAX_FLAGS) $(BINDINGS_DIR)/ot0cli.scm

# TODO: compute these!
OT0_GAMBITC_SOURCES=ot0.c irregex.c

OT0_OBJECTS=ot0-hooks.o ot0.o

OT0_CLI_GAMBITC_FILES=$(MATCH_DIR)/match.c $(LIKELY_DIR)/likely.gambit.c $(LWIP_DIR)/lwip.c \
	ot0use.c ot0cli.c #  irregex.c

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

OT0_CLI_OBJECTS=$(MATCH_DIR)/match.o likely.gambit.o lwip.o irregex.o ot0use.o ot0cli.o ot0cli_.o

ot0: $(OT0_CLI_OBJECTS) $(OT0_OBJECTS) libzerotiercore.a
	$(CXX) -o ot0 -L. -L $(SYS_ROOT)/lib $(OT0_OBJECTS) $(OT0_CLI_OBJECTS) \
	 -lzerotiercore -llwipcore -lgambit -ldl -lutil

test: # Test It
test: ot0
	./ot0 -tests $(BINDINGS_DIR)/ot0-tests.scm : -exit

vg: # run under valgrind
vg:
	valgrind --log-file=/tmp/ds-vg.log --track-origins=yes  --read-inline-info=yes --read-var-info=yes --leak-check=full --show-leak-kinds=all ./ot0 -B a -S ot0 start "\"$(IPADDR1):9994\"" $(OT0A) -repl

testdata: # nome est omen
testdata: z a b y

z:
	./ot0 -1-i z

a b:
	./ot0 -A $@

IPADDR1=192.168.41.96
IPADDR2=192.168.41.95
OT0PORT=9994
OT0_ALL_EDGES=$(IPADDR1) $(OT0PORT) # $(IPADDR2) $(OT0PORT)

y: a b z
	./ot0 -data vertex make y type: origin nonce: 23 kp: z edge: `cat a/identifier` $(OT0_ALL_EDGES) :
	./ot0 -B a -adm origin:= y
	./ot0 -B b -adm origin:= y

#OT0DBG?=-d:a9 -k s -d t wire -d t ot0 -l xx.scm
NETWORK_NR=18374687579166474240 # 18382870269589979136
OT0JOIN=join: $(NETWORK_NR)
#OT0VIA=via: 652295435805

OT0A=$(OT0ADDIP) $(OT0VIA) $(OT0JOIN)

# Forward to Bob (#x6a6ec212c9) on NW 18382870269589979136
# OT0A += -service tcp forward 13443 BEWARE: REPLACE the IPv6 address with the output of:
#         make addr-b
#OT0A +=	-service tcp forward 13443 "[fcec:xx:xxxx:xxxx:xxxx::1]:7443"
OT0A +=	-service tcp forward 13443 "[fcec:1d13:1d6a:6ec2:12c9::1]:7443"

a-run:	# start 'a'
a-run:
	./ot0 $(OT0DBG) -B a ip: on -S control 9091 : -S ot0 start "\"$(IPADDR1):9994\"" $(OT0A) -repl

#OT0B?=contact: `cat a/identifier` $(IPADDR1)/9994
OT0B += $(OT0ADDIP) $(OT0VIA) $(OT0JOIN)

OT0B += -service vpn tcp forward 7443 127.0.0.1:2020

addr-b:
	./ot0 -data net 6plane $(NETWORK_NR) \
	\#x`./ot0 -data id print b/identifier | cut -d: -f 1` 7443 | cut -d / -f 1

b-run:	# start 'b'
b-run:
	./ot0 $(OT0DBG) -B b ip: on -S control 9092 : -S ot0 start "\"$(IPADDR1):9995\"" $(OT0B) -repl


weg: force
	-rm $(OT0_CLI_GAMBITC_FILES) $(OT0_GAMBITC_SOURCES) $(OT0_OBJECTS) $(OT0_CLI_OBJECTS)

xclean:	# remove backupfiles (*~)
xclean: force
	rm -f `find . -type f -name "*~" -print`
force:

help:	# help on possible targets
	-@egrep "^[-A-Za-z0-9\._]+::?.*#" [Mm]akefile
