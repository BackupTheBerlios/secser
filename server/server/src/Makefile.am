AM_CPPFLAGS = -I.. -I$(top_srcdir)/src/include -I./util -I./g10
common_lib = ./g10/libgpg.a ./cipher/libcipher.a ./mpi/libmpi.a ./util/libutil.a
SUBDIRS = g10 util mpi cipher zlib
bin_PROGRAMS = adhoc secretkey secretsign
adhoc_SOURCES = main.c udp_server.c receive.c process.c handle.c parser.c route.c ip_addr.c initfunc.c \
                 systemsign.c interpolate.c semaphore.c signal.c 
adhoc_LDADD = $(common_lib) ./zlib/libzlib.a
adhoc_DEPENDENCIES = $(common_lib) ./zlib/libzlib.a
secretkey_SOURCES = secretkey.c initfunc.c
secretkey_DEPENDENCIES = $(common_lib) ./zlib/libzlib.a
secretkey_LDADD = $(common_lib) ./zlib/libzlib.a
secretsign_SOURCES = secretsign.c initfunc.c interpolate.c
secretsign_DEPENDENCIES = $(common_lib) ./zlib/libzlib.a
secretsign_LDADD = $(common_lib) ./zlib/libzlib.a
