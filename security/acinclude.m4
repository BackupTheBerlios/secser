AC_DEFUN(ADHOC_CHECK_TYPEDEF,
  [ AC_MSG_CHECKING(for $1 typedef)
    AC_CACHE_VAL(adhoc_cv_typedef_$1,
    [AC_TRY_COMPILE([#define _GNU_SOURCE 1
    #include <stdlib.h>
    #include <sys/types.h>], [
    #undef $1
    int a = sizeof($1);
    ], adhoc_cv_typedef_$1=yes, adhoc_cv_typedef_$1=no )])
    AC_MSG_RESULT($adhoc_cv_typedef_$1)
    if test "$adhoc_cv_typedef_$1" = yes; then
        AC_DEFINE($2,1,[Defined if a `]$1[' is typedef'd])
    fi
  ])

