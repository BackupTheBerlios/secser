# Process this file with autoconf to produce a configure script.
AC_INIT(adhoc,0.1 , BUG-REPORT-ADDRESS)
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE(adhoc, 0.1)
AM_CONFIG_HEADER(config.h)

AH_BOTTOM([
#include "defs.h"
])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([errno.h fcntl.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h langinfo.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM
AC_TYPE_UID_T

ADHOC_CHECK_TYPEDEF(byte, HAVE_BYTE_TYPEDEF)
ADHOC_CHECK_TYPEDEF(ushort, HAVE_USHORT_TYPEDEF)
ADHOC_CHECK_TYPEDEF(ulong, HAVE_ULONG_TYPEDEF)
ADHOC_CHECK_TYPEDEF(u16, HAVE_U16_TYPEDEF)
ADHOC_CHECK_TYPEDEF(u32, HAVE_U32_TYPEDEF)


AC_CHECK_SIZEOF(unsigned short, 2)
AC_CHECK_SIZEOF(unsigned int, 4)
AC_CHECK_SIZEOF(unsigned long, 4)
AC_CHECK_SIZEOF(unsigned long long, 0)


try_gettext=yes
case "${target}" in
    *-*-mingw32*)
        # special stuff for Windoze NT
        ac_cv_have_dev_random=no
        AC_DEFINE(USE_ONLY_8DOT3,1,
                  [set this to limit filenames to the 8.3 format])
        AC_DEFINE(HAVE_DRIVE_LETTERS,1,
                  [defined if we must run on a stupid file system])
        AC_DEFINE(HAVE_DOSISH_SYSTEM,1,
                  [defined if we run on some of the PCDOS like systems
                   (DOS, Windoze. OS/2) with special properties like
                    no file modes])
        AC_DEFINE(USE_SIMPLE_GETTEXT,1,
                  [because the Unix gettext has too much overhead on
                   MingW32 systems and these systems lack Posix functions,
                   we use a simplified version of gettext])
        try_gettext="no"
        ;;
    i?86-emx-os2 | i?86-*-os2*emx )
        # OS/2 with the EMX environment
        ac_cv_have_dev_random=no
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        AC_DEFINE(HAVE_DOSISH_SYSTEM)
        try_gettext="no"
        ;;

    i?86-*-msdosdjgpp*)
        # DOS with the DJGPP environment
        ac_cv_have_dev_random=no
        AC_DEFINE(HAVE_DRIVE_LETTERS)
        AC_DEFINE(HAVE_DOSISH_SYSTEM)
        try_gettext="no"
        ;;

    *-*-freebsd*)
       # FreeBSD
       CPPFLAGS="$CPPFLAGS -I/usr/local/include"
       LDFLAGS="$LDFLAGS -L/usr/local/lib"
       ;;

    *-*-hpux*)
        if test -z "$GCC" ; then
            CFLAGS="$CFLAGS -Ae -D_HPUX_SOURCE"
        fi
        ;;
    *-dec-osf4*)
        if test -z "$GCC" ; then
            # Suppress all warnings
            # to get rid of the unsigned/signed char mismatch warnings.
            CFLAGS="$CFLAGS -w"
        fi
        ;;
    *-dec-osf5*)
        if test -z "$GCC" ; then
            # Use the newer compiler `-msg_disable ptrmismatch' to
            # get rid of the unsigned/signed char mismatch warnings.
            # Using this may hide other pointer mismatch warnings, but
            # it at least lets other warning classes through
            CFLAGS="$CFLAGS -msg_disable ptrmismatch"
        fi
        ;;
    m68k-atari-mint)
        ;;
    *)
       ;;
esac



if test "$ac_cv_sizeof_unsigned_short" = "0" \
   || test "$ac_cv_sizeof_unsigned_int" = "0" \
   || test "$ac_cv_sizeof_unsigned_long" = "0"; then
    AC_MSG_WARN([Hmmm, something is wrong with the sizes - using defaults]);
fi

#
# 1. Set names of random devices
#
NAME_OF_DEV_RANDOM="/dev/random"
NAME_OF_DEV_URANDOM="/dev/urandom"
case "${target}" in
    *-openbsd*)
        NAME_OF_DEV_RANDOM="/dev/srandom"
        NAME_OF_DEV_URANDOM="/dev/urandom"
        ;;
esac
AC_DEFINE_UNQUOTED(NAME_OF_DEV_RANDOM, "$NAME_OF_DEV_RANDOM",
                   [defined to the name of the strong random device])
AC_DEFINE_UNQUOTED(NAME_OF_DEV_URANDOM, "$NAME_OF_DEV_URANDOM",
                   [defined to the name of the weaker random device])
AC_DEFINE(USE_RNDLINUX,1,
                  [Defined if the /dev/random based RNG should be used.])

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_TYPE_SIGNAL
AC_FUNC_WAIT3
AC_CHECK_FUNCS([clock_gettime dup2 gethrtime gettimeofday memmove memset select socket])
AC_CHECK_FUNCS(strerror stpcpy strsep strlwr tcgetattr strtoul mmap)
AC_CHECK_FUNCS(strcasecmp strncasecmp)
AC_CHECK_FUNCS(memmove gettimeofday getrusage setrlimit clock_gettime)
AC_CHECK_FUNCS(atexit raise getpagesize strftime nl_langinfo setlocale)
AC_CHECK_FUNCS(waitpid wait4 sigaction sigprocmask rand pipe stat)

AC_MSG_CHECKING(for extra cipher modules)
tmp=""
if test -f $srcdir/src/cipher/idea.c; then
   IDEA_O=idea.o
   tmp=idea
else
   IDEA_O=idea-stub.o
   tmp=no
fi
AC_SUBST(IDEA_O)
AC_MSG_RESULT($tmp)


AC_SUBST(TIGER_O,tiger.o)
AC_DEFINE(USE_TIGER,1,[Define to include experimental TIGER digest support])

AC_MSG_CHECKING(for mpi assembler functions)
if test -f $srcdir/src/mpi/config.links ; then
    . $srcdir/src/mpi/config.links
    AC_CONFIG_LINKS("$mpi_ln_list")
    ac_cv_mpi_extra_asm_modules="$mpi_extra_modules"
    ac_cv_mpi_sflags="$mpi_sflags"
    ac_cv_mpi_config_done="yes"
    AC_MSG_RESULT(done)
else
    AC_MSG_RESULT(failed)
    AC_MSG_ERROR([mpi/config.links missing!])
fi
MPI_EXTRA_ASM_OBJS=""
show_extraasm=""
if test "$ac_cv_mpi_extra_asm_modules" != ""; then
for i in $ac_cv_mpi_extra_asm_modules; do
    show_extraasm="$show_extraasm $i"
    MPI_EXTRA_ASM_OBJS="$MPI_EXTRA_ASM_OBJS $i.o"
done
fi
AC_SUBST(MPI_EXTRA_ASM_OBJS)
MPI_SFLAGS="$ac_cv_mpi_sflags"
MPI_OPT_FLAGS=""
AC_SUBST(MPI_OPT_FLAGS)

AM_CONDITIONAL(ENABLE_LOCAL_ZLIB, true)
    AC_CONFIG_LINKS(zlib.h:src/zlib/zlib.h zconf.h:src/zlib/zconf.h )
    ZLIBS="zlib/libzlib.a"
AC_SUBST(ZLIBS)

AC_CONFIG_COMMANDS(defs.h,[[
cat >defs.tmp <<ADHOCEOF
/* generated automatically by configure */
#ifdef HAVE_DRIVE_LETTERS
  #define ADHOC_LOCALEDIR     "c:\\\\lib\\\\adhoc\\\\locale"
  #define ADHOC_LIBDIR      "c:\\\\lib\\\\adhoc"
  #define ADHOC_LIBEXECDIR  "c:\\\\lib\\\\adhoc"
  #define ADHOC_DATADIR     "c:\\\\lib\\\\adhoc"
  #define ADHOC_HOMEDIR     "c:\\\\adhoc"
#else
  #define ADHOC_LOCALEDIR     "${datadir}/locale"
  #define ADHOC_LIBDIR      "${libdir}/adhoc"
  #define ADHOC_LIBEXECDIR  "${libexecdir}/adhoc"
  #define ADHOC_DATADIR     "${datadir}/adhoc"
  #ifdef __VMS
    #define ADHOC_HOMEDIR "/SYS\$LOGIN/adhoc"
  #else
    #define ADHOC_HOMEDIR ".adhoc"
  #endif
#endif
/* those are here to be redefined by handcrafted g10defs.h.
   Please note that the string version must not contain more
   than one character because the using code assumes strlen()==1 */
#ifdef HAVE_DOSISH_SYSTEM
#define DIRSEP_C '\\\\'
#define EXTSEP_C '.'
#define DIRSEP_S "\\\\"
#define EXTSEP_S "."
#else
#define DIRSEP_C '/'
#define EXTSEP_C '.'
#define DIRSEP_S "/"
#define EXTSEP_S "."
#endif
ADHOCEOF
cat src/mpi/generic/mpi-asm-defs.h >>defs.tmp
if cmp -s defs.h defs.tmp 2>/dev/null; then
    echo "defs.h is unchanged"
    rm -f defs.tmp
else
    rm -f defs.h
    mv defs.tmp defs.h
    echo "defs.h created"
fi
]],[[
prefix=$prefix
exec_prefix=$exec_prefix
libdir=$libdir
libexecdir=$libexecdir
datadir=$datadir
DATADIRNAME=$DATADIRNAME
]])


case "${target}" in
    *-*-mingw32*)
        PRINTABLE_OS_NAME="MingW32"
        ;;
    *-*-cygwin*)
        PRINTABLE_OS_NAME="Cygwin"
        ;;
    i?86-emx-os2 | i?86-*-os2*emx )
        PRINTABLE_OS_NAME="OS/2"
        ;;
    i?86-*-msdosdjgpp*)
        PRINTABLE_OS_NAME="MSDOS/DJGPP"
        try_dynload=no
        ;;
    *-linux*)
        PRINTABLE_OS_NAME="GNU/Linux"
        ;;
dnl let that after linux to avoid gnu-linux problems
    *-gnu*)
        PRINTABLE_OS_NAME="GNU/Hurd"
        ;;
    *)
        PRINTABLE_OS_NAME=`uname -s || echo "Unknown"`
        ;;
esac
AC_DEFINE_UNQUOTED(PRINTABLE_OS_NAME, "$PRINTABLE_OS_NAME",
                   [A human readable text with the name of the OS])

AC_DEFINE_UNQUOTED(EXTSEP_S, ".",
                   [Extension separator])

AC_OUTPUT(Makefile src/Makefile src/g10/Makefile src/util/Makefile src/mpi/Makefile src/cipher/Makefile src/zlib/Makefile)
