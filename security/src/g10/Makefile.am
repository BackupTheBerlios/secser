# Copyright (C) 1998, 1999, 2000, 2001, 2002 Free Software Foundation, Inc.
#
# This file is part of GnuPG.
#
# GnuPG is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# GnuPG is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA

## Process this file with automake to produce Makefile.in

INCLUDES = -I.. -I../.. -I$(top_srcdir)/src/include 
EXTRA_DIST = options.skel
# it seems that we can't use this with automake 1.5
#OMIT_DEPENDENCIES = zlib.h zconf.h
LDFLAGS = @LDFLAGS@ 
#needed_libs = ../cipher/libcipher.a ../mpi/libmpi.a ../util/libutil.a

#noinst_PROGRAMS = gpgd
noinst_LIBRARIES = libgpg.a

common_source =  \
	      global.h          \
	      build-packet.c	\
	      compress.c	\
	      filter.h		\
	      free-packet.c	\
	      getkey.c		\
	      keydb.c keydb.h    \
	      keyring.c keyring.h \
	      seskey.c		\
	      kbnode.c		\
	      main.h		\
	      mainproc.c	\
	      armor.c		\
	      mdfilter.c	\
	      textfilter.c	\
	      misc.c		\
	      options.h 	\
	      openfile.c	\
	      keyid.c		\
	      packet.h		\
	      parse-packet.c	\
	      comment.c 	\
	      status.c		\
	      status.h		\
	      plaintext.c	\
	      sig-check.c	\
	      keylist.c 	\
	      signal.c

libgpg_a_SOURCES  = 		\
	      $(common_source)	\
	      pkclist.c 	\
	      skclist.c 	\
	      pubkey-enc.c	\
	      passphrase.c	\
	      seckey-cert.c	\
	      encr-data.c	\
	      cipher.c		\
	      encode.c		\
	      sign.c		\
	      verify.c		\
	      revoke.c		\
	      decrypt.c 	\
	      keyedit.c 	\
	      dearmor.c 	\
	      import.c		\
	      export.c		\
	      hkp.h		\
	      hkp.c		\
	      trustdb.c 	\
	      trustdb.h 	\
	      tdbdump.c 	\
	      tdbio.c		\
	      tdbio.h		\
	      delkey.c		\
	      keygen.c          \
	      pipemode.c        \
	      helptext.c        \
	      keyserver.c       \
	      keyserver-internal.h \
	      photoid.c photoid.h \
	      exec.c exec.h


