# Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
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
CFLAGS = @CFLAGS@ @MPI_OPT_FLAGS@
ASFLAGS = @MPI_SFLAGS@

EXTRA_DIST = config.links
DISTCLEANFILES = mpi-asm-defs.h \
                 mpih-add1.S mpih-mul1.S mpih-mul2.S mpih-mul3.S  \
		 mpih-lshift.S mpih-rshift.S mpih-sub1.S asm-syntax.h sysdep.h
# Note: we only use .S files so we should delete all left over .s
CLEANFILES = _*.s

noinst_LIBRARIES = libmpi.a

# libmpi_a_LDFLAGS =
libmpi_a_SOURCES = longlong.h	  \
	      mpi-add.c      \
	      mpi-bit.c      \
	      mpi-cmp.c      \
	      mpi-div.c      \
	      mpi-gcd.c      \
	      mpi-internal.h \
	      mpi-inline.h   \
	      mpi-inline.c   \
	      mpi-inv.c      \
	      mpi-mul.c      \
	      mpi-pow.c      \
	      mpi-mpow.c     \
	      mpi-scan.c     \
	      mpicoder.c     \
	      mpih-cmp.c     \
	      mpih-div.c     \
	      mpih-mul.c     \
	      mpiutil.c      \
	      g10m.c

# Note this objects are actually links, the sourcefiles are
# distributed by special code in dist-hook
common_asm_objects = mpih-mul1.o    \
		     mpih-mul2.o    \
		     mpih-mul3.o    \
		     mpih-add1.o    \
		     mpih-sub1.o    \
		     mpih-lshift.o  \
		     mpih-rshift.o

libmpi_a_DEPENDENCIES = $(common_asm_objects) @MPI_EXTRA_ASM_OBJS@
libmpi_a_LIBADD = $(common_asm_objects) @MPI_EXTRA_ASM_OBJS@

# cancel the default rules used by libtool which do not really
# work and add one to cpp .S files
.S.o:
	 $(CPP) $(INCLUDES) $(DEFS) $< | grep -v '^#' > _$*.s
	 $(COMPILE) -c _$*.s
	 mv -f _$*.o $*.o

.S.lo:


