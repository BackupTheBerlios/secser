#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>

#define INCLUDED_BY_MAIN_MODULE 1
#include "util.h"
#include "iobuf.h"
#include "mpi.h"
#include "memory.h"
#include "options.h"
#include "packet.h"
#include "globals.h"
#include "adhoc.h"

#define NAME "systemkey"
#define STDPUB "public"
#define STDSEC "secret"
#define STDLIST "idlist.txt"
#define STDEXT ".key"

#define CMDGEN 1
#define CMDSPLIT 2
#define CMDCHECK 4

#define FBITS 160               /* Number of bits for polynomial coeficient */

int g10_errors_seen;

/* Description of long options */

static const struct option long_options[] = {
  {"gen-key", 1, NULL, 'g'},
  {"split-key", 1, NULL, 's'},
  {"sec-file", 1, NULL, 'f'},
  {"id-list", 1, NULL, 'i'},
  {"check", 1, NULL, 'c'},
  {"help", 0, NULL, 'h'},
  {"verbose", 0, NULL, 'v'},
};

/* Description of short options */

static const char *const short_options = "g:s:f:i:c:hv";

/* Usage summary text */

static const char *const usage_help =
  "Usage: %s [ options ]\n"
  "Options:\n"
  "  -g,  --gen-key FILE            Generate 1024 bits RSA system key.\n"
  "                                   Configuration of the key and output\n"
  "                                   file must be specified in FILE\n"
  "  -s,  --split-key  N            Split key into N part\n"
  "  -f,  --sec-file FILE           Secret key file name.\n"
  "                                   Used as input for spliting key.\n"
  "  -i,  --id-list FILE            File contains list of user ID.\n"
  "                                   We use IP Address as ID here.\n"
  "  -c,  --check FILE              Check a file whether or not it\n"
  "                                   contains a secret key.\n"
  "  -h,  --help                    Print this information text.\n"
  "  -v,  --verbose                 Working in verbose mode.\n";


/* Global variables definition */

int verbose = 0;
struct in_addr *list[MAXSPLIT];


void
print_help (int err)
{
  if (err == 1)
    {
      fprintf (stderr, "Sorry, you have specified wrong option\n");
      fprintf (stderr, usage_help, NAME);
    }
  if (err == 2)
    {
      fprintf (stderr, "You must specify whether to generate or split key\n");
      fprintf (stderr, usage_help, NAME);
    }
  else
    fprintf (stdout, usage_help, NAME);
  exit (err ? 1 : 0);
}

int
systemkey_parse_id (FILE * fd, int num)
{
  char addr[16];
  int err = 0;
  int cnt = 0;
  int i = 0;

  do
    {
      do
        {
          /* parse one line, maximum 15 characters for IPV4 */
          addr[cnt] = fgetc (fd);
          cnt++;
        }
      while ((cnt < 16) && (addr[cnt - 1] != '\n'));
      if ((cnt == 16) && (addr[cnt - 1] != '\n'))
        {
          err = 1;
          break;
        }
      addr[cnt - 1] = 0;

      if (verbose)
        printf ("Address %u: %s\n", i + 1, addr);

      /* Translate into unsigned long int and put on the list */
      list[i] = (struct in_addr *) m_alloc (sizeof (struct in_addr));
      if (!inet_aton (addr, list[i]))
        {
          err = 1;
          break;
        }
      i++;
      cnt = 0;
    }
  while (!err && i < num);

  if (err)
    for (cnt = 0; cnt < i; cnt++)
      m_free (list[cnt]);

  return err;
}

int
systemkey_write_key (PKT_secret_key * sk, MPI d, char *name, int index)
{
  IOBUF out = NULL;
  KBNODE sec_root = NULL;
  PACKET *pkt;
  PKT_secret_key *key;
  char *outname = (char *) m_alloc (strlen (name) + 2 + 4 + 1); // max index is MAXSPLIT (2 digits), .key \0
  int rc;

  sprintf (outname, "%s%u" STDEXT, name, index);

  /* prepare iobuf */
  out = iobuf_create (outname);
  if (!out)
    {
      rc = 1;
      goto leave;
    }

  /* preparing node */
  sec_root = make_comment_node ("#");
  delete_kbnode (sec_root);

  key = m_alloc_clear (sizeof *key);
  key->timestamp = sk->timestamp;
  key->version = sk->version;
  key->expiredate = sk->expiredate;
  key->pubkey_algo = sk->pubkey_algo;
  key->skey[0] = mpi_copy (sk->skey[0]);
  key->skey[1] = mpi_copy (sk->skey[1]);
  key->skey[2] = d;
  key->skey[3] = mpi_alloc_set_ui (1);
  key->skey[4] = mpi_alloc_set_ui (1);
  key->skey[5] = mpi_alloc_set_ui (1);
  key->is_protected = sk->is_protected;
  key->protect.algo = sk->protect.algo;
  key->csum = checksum_mpi (key->skey[2]);
  key->csum += checksum_mpi (key->skey[3]);
  key->csum += checksum_mpi (key->skey[4]);
  key->csum += checksum_mpi (key->skey[5]);

  pkt = m_alloc_clear (sizeof *pkt);
  pkt->pkttype = PKT_SECRET_KEY;
  pkt->pkt.secret_key = key;

  rc = build_packet (out, pkt);

  if (rc)
    iobuf_cancel (out);
  else
    iobuf_close (out);
  free_packet (pkt);
leave:
  free (outname);
  return rc;
}

void
systemkey_check (char *name)
{
  PACKET *pkt = m_alloc (sizeof *pkt);
  PKT_secret_key *sk;
  IOBUF inp = NULL;
  int i, n;

  if (!(inp = iobuf_open (name)))
    {
      m_free (pkt);
      printf ("Error opening file for checking\n");
      return;
    }

  init_packet (pkt);
  if (parse_packet (inp, pkt))
    {
      printf ("Error parsing packet file\n");
      goto leave;
    }

  if (pkt->pkttype == PKT_SECRET_KEY)
    {
      sk = pkt->pkt.secret_key;
      printf ("Secret key found\n");
      printf ("Key type : %s\n", pubkey_algo_to_string (sk->pubkey_algo));
      printf ("Key version : %u\n", sk->version);
      printf ("---- START SECRET KEY DATA -----\n");
      n = pubkey_get_nskey (sk->pubkey_algo);
      for (i = 0; i < n; i++)
        {
          printf ("Key %u: ", i);
          mpi_print (stdout, sk->skey[i], 1);
          printf ("\n");
        }
    }

leave:
  free_packet (pkt);
  iobuf_close (inp);
}

int
systemkey_split (char *sec, char *id, int num)
{
  FILE *fd = NULL;
  PACKET *pkt = m_alloc (sizeof *pkt);
  PKT_secret_key *sk;
  IOBUF inp = NULL;
  int i, n, j;
  int rc = 0;
  MPI f[MAXSPLIT - 1];
  MPI tmp = mpi_alloc (0);
  MPI res[MAXSPLIT];
  char *p;

  if (!(inp = iobuf_open (sec)))
    {
      m_free (pkt);
      return 1;
    }

  if (!(fd = fopen (id, "r")))
    {
      rc = 2;
      goto leave;
    }

  /* Parse id file */
  if (systemkey_parse_id (fd, num))
    {
      rc = 5;
      goto leave;
    }

  /* We have everything now */
  init_packet (pkt);
  if (parse_packet (inp, pkt))
    {
      rc = 3;
      goto leave;
    }

  if (pkt->pkttype == PKT_SECRET_KEY)
    {
      sk = pkt->pkt.secret_key;

      if (verbose)
        {
          printf ("Secret key found\n");
          printf ("Key type : %u\n", sk->pubkey_algo);
          printf ("Key version : %u\n", sk->version);
        }

      /* Preparing result fields */
      for (j = 0; j < num; j++)
        res[j] = mpi_alloc (0);

      /* Generate random number num - 1 times */
      for (i = 0; i < (num - 1); i++)
        {

          /* We are using FBITS bits of f */
          f[i] =
            mpi_alloc ((FBITS + BITS_PER_MPI_LIMB - 1) / BITS_PER_MPI_LIMB);
          p = get_random_bits (FBITS, 0, 0);
          mpi_set_buffer (f[i], p, (FBITS + 7) / 8, 0);

          /* calculate polynomial result for each id */
          for (j = 0; j < num; j++)
            {
              /* tmp = fi */
              mpi_set (tmp, f[i]);

              /* tmp = fi*id^(i+1) */
              for (n = 0; n < (i + 1); n++)
                {
                  mpi_mul_ui (tmp, tmp, list[j]->s_addr);
                }

              /* res = res + tmp */
              mpi_add (res[j], res[j], tmp);
            }

          m_free (p);
          if (verbose)
            {
              printf ("\nCoeficient %u: ", i);
              mpi_print (stdout, f[i], 1);
            }

        }

      for (j = 0; j < num; j++)
        {
          /* res = (res + SK) mod N */
          mpi_add (res[j], res[j], sk->skey[2]);
          /* We should not mod with sk->skey[0], while result will be different
           * however, here we use relatively small coeficient for polynomial,
           * so partial key won't be bigger then sk->skey[0]
           */
          mpi_fdiv_r (res[j], res[j], sk->skey[0]);

          if (verbose)
            {
              printf ("\nresult Nr. %u: ", j);
              mpi_print (stdout, res[j], 1);
            }

          /* write to file, res[j] will be freed */
          if (systemkey_write_key (sk, res[j], sec, j))
            {
              /* We can not continue here, free the rest of res[j] */
              for (; j < num; j++)
                mpi_free (res[j]);
            }

        }
      printf ("\n");

      for (i = 0; i < (num - 1); i++)
        {
          mpi_free (f[i]);
        }
      mpi_free (tmp);
    }
  else
    {
      rc = 4;
    }

leave:
  free_packet (pkt);
  iobuf_close (inp);
  if (fd)
    fclose (fd);
  return rc;
}

int
main (int argc, char **argv)
{
  int next_option;
  int rc;
  int cmd = 0;

  long split_num;
  char *confname = NULL;
  char *secname = NULL;
  char *idname = NULL;
  char *checkname = NULL;

  /* Initialize gpg environment */
  init ("systemkey");

  /* We use configuration file for generating key */
  opt.batch = 1;

  if (argc < 2)
    print_help (0);

  /* Parse all options first */
  do
    {
      next_option =
        getopt_long (argc, argv, short_options, long_options, NULL);
      switch (next_option)
        {
        case 'h':
          /* User specified -h or --help */
          {
            print_help (0);
          }

        case 'g':
          /* User specified -g or --gen-key */
          {
            cmd |= CMDGEN;
            confname = (char *) strdup (optarg);
          }
          break;

        case 's':
          /* User specified -s or --split-key */
          {
            char *end;

            cmd |= CMDSPLIT;
            split_num = strtol (optarg, &end, 10);
            if (*end != '\0')
              /* User specified nondigits in number of split. */
              print_help (1);
          }
          break;

        case 'f':
          /* User specified -f or --sec-file */
          {
            secname = (char *) strdup (optarg);
          }
          break;

        case 'i':
          /* User specified -i or --id-list */
          {
            idname = (char *) strdup (optarg);
          }
          break;

        case 'c':
          /* User specified -c or --check */
          {
            cmd |= CMDCHECK;
            checkname = (char *) strdup (optarg);
          }
          break;

        case 'v':
          /* User specified -v or --verbose */
          verbose = 1;
          break;

        case '?':
          /* User specified an unrecognized option. */
          print_help (1);

        case -1:
          /* Done with options. */
          break;

        default:
          /* User specified unknown option */
          {
            print_help (1);
          }
        }
    }
  while (next_option != -1);

  /* We need no more options. Issue an error if the user specified any. */
  if (optind != argc)
    print_help (1);

  /* Initialize secure memory */
  secmem_init (16384);

  /* no command, whether to generate or split key */
  if (!cmd)
    print_help (2);

  if (cmd > CMDCHECK)
    {
      printf ("You can not check partial key file,\n"
              "and combine it with other command!!\n");
      exit (0);
    }

  if (cmd & CMDCHECK)
    {
      systemkey_check (checkname);
      m_free (checkname);
    }
  else
    {
      if (cmd & CMDGEN)
        {
          if (verbose)
            printf ("Generating key, reading %s.....\n", confname);

          generate_keypair (confname);

          m_free (confname);
        }

      if (cmd & CMDSPLIT)
        {
          if (verbose)
            printf ("Spliting key into %u parts.....\n", split_num);
          if (!secname)
            {
              printf ("No secret key file name specified, trying " STDSEC
                      STDEXT "\n");
              secname = (char *) strdup (STDSEC STDEXT);
            }
          if (!idname)
            {
              printf ("No id list file specified, trying " STDLIST "\n");
              idname = (char *) strdup (STDLIST);
            }
          rc = systemkey_split (secname, idname, split_num);
          if (rc == 1)
            printf ("Can not open secret key file\n");
          else if (rc == 2)
            printf ("Can not open id list file\n");
          else if (rc == 5)
            printf ("Error while parsing id list file\n");
          else if (rc)
            printf ("Error %u....!!!\n", rc);

          m_free (secname);
          m_free (idname);
        }
    }
leave:
  secmem_term ();
  exit (0);
}
