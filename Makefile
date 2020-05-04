# Common makefile -- loads make rules for each platform

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

xclean:	# remove backupfiles (*~)
xclean: force
	rm -f `find . -type f -name "*~" -print`
force:

help:	# help on possible targets
	-@egrep "^[-A-Za-z0-9\._]+::?.*#" [Mm]akefile
