# Common makefile -- loads make rules for each platform

### FIXME: ZT_DEBUG=1 is currently required.  Otherwise the build hangs!.
ZT_DEBUG ?= 1
ZT_JSON_SUPPORT ?= 1

OSTYPE?=$(shell uname -s)

VERSION=0.1.4
NAME=onetierzero

dist: force
	tar --exclude .git --exclude *.tar* \
		--exclude *.o --exclude '*.a' --exclude '*.so' --exclude '*.obj' --exclude '*.dll' \
		-czf $(NAME)-$(VERSION).tar.gz *

force:

ifeq ($(OSTYPE),Darwin)
  include make-mac.mk
endif

ifeq ($(OSTYPE),Linux)
  include make-linux.mk
endif

ifeq ($(OSTYPE),FreeBSD)
  CC?=clang
  CXX?=clang++
  ZT_BUILD_PLATFORM=7
  include make-bsd.mk
endif
ifeq ($(OSTYPE),OpenBSD)
  CC?=egcc
  CXX?=eg++
  ZT_BUILD_PLATFORM=9
  include make-bsd.mk
endif

ifeq ($(OSTYPE),NetBSD)
  include make-netbsd.mk
endif

ifeq ($(OSTYPE),Win32)
  include make-bsd.mk
endif
