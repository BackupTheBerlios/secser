#include <stdio.h>
#include <stdlib.h>

#include "adhoc.h"
#include "options.h"

void
i18n_init (void)
{
#ifdef USE_SIMPLE_GETTEXT
  set_gettext_file (PACKAGE);
#else
#ifdef ENABLE_NLS
  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, G10_LOCALEDIR);
  textdomain (PACKAGE);
#endif
#endif
}

void
init (char *logname)
{
  trap_unaligned ();
  secmem_set_flags (secmem_get_flags () | 2);
  log_set_name (logname);
  secure_random_alloc ();
  create_dotlock (NULL);
  i18n_init ();
  opt.command_fd = -1;
  opt.compress = -1;
  opt.def_cipher_algo = 0;
  opt.def_digest_algo = 0;
  opt.cert_digest_algo = 0;
  opt.def_compress_algo = -1;
  opt.s2k_mode = 3;             /* iterated+salted */
  opt.s2k_digest_algo = DIGEST_ALGO_SHA1;
  opt.s2k_cipher_algo = CIPHER_ALGO_CAST5;
  opt.completes_needed = 1;
  opt.marginals_needed = 3;
  opt.max_cert_depth = 5;
  opt.pgp2_workarounds = 1;
  opt.force_v3_sigs = 1;
  opt.escape_from = 1;
  opt.import_options = 0;
  opt.export_options = opt.debug = 0;
  EXPORT_INCLUDE_NON_RFC | EXPORT_INCLUDE_ATTRIBUTES;
  opt.keyserver_options.import_options = IMPORT_REPAIR_HKP_SUBKEY_BUG;
  opt.keyserver_options.export_options =
    EXPORT_INCLUDE_NON_RFC | EXPORT_INCLUDE_ATTRIBUTES;
  opt.keyserver_options.include_subkeys = 1;
  opt.keyserver_options.include_revoked = 1;
  return;
}



void
g10_exit (int rc)
{
  update_random_seed_file ();
  if (opt.debug & DBG_MEMSTAT_VALUE)
    {
      m_print_stats ("on exit");
      random_dump_stats ();
    }
  if (opt.debug)
    secmem_dump_stats ();
  secmem_term ();
  rc = rc ? rc : log_get_errorcount (0) ? 2 : g10_errors_seen ? 1 : 0;
  exit (rc);
}
