/* generated automatically by configure */
#ifdef HAVE_DRIVE_LETTERS
  #define ADHOC_LOCALEDIR     "c:\\lib\\adhoc\\locale"
  #define ADHOC_LIBDIR      "c:\\lib\\adhoc"
  #define ADHOC_LIBEXECDIR  "c:\\lib\\adhoc"
  #define ADHOC_DATADIR     "c:\\lib\\adhoc"
  #define ADHOC_HOMEDIR     "c:\\adhoc"
#else
  #define ADHOC_LOCALEDIR     "/usr/local/share/locale"
  #define ADHOC_LIBDIR      "/usr/local/lib/adhoc"
  #define ADHOC_LIBEXECDIR  "/usr/local/libexec/adhoc"
  #define ADHOC_DATADIR     "/usr/local/share/adhoc"
  #ifdef __VMS
    #define ADHOC_HOMEDIR "/SYS$LOGIN/adhoc"
  #else
    #define ADHOC_HOMEDIR ".adhoc"
  #endif
#endif
/* those are here to be redefined by handcrafted g10defs.h.
   Please note that the string version must not contain more
   than one character because the using code assumes strlen()==1 */
#ifdef HAVE_DOSISH_SYSTEM
#define DIRSEP_C '\\'
#define EXTSEP_C '.'
#define DIRSEP_S "\\"
#define EXTSEP_S "."
#else
#define DIRSEP_C '/'
#define EXTSEP_C '.'
#define DIRSEP_S "/"
#define EXTSEP_S "."
#endif
/* This file defines some basic constants for the MPI machinery.  We
 * need to define the types on a per-CPU basis, so it is done with
 * this file here.  */
#define BYTES_PER_MPI_LIMB  (SIZEOF_UNSIGNED_LONG)






