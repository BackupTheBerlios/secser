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

#define NAME "systemsign"

#define LF "\n"

#define CMDSIGN  1
#define CMDJOIN  2
#define CMDCHECK 3

#define DEFOUT "output"
#define DEFEXT ".txt"

/* Description of long options */

static const struct option long_options[] = {
  {"sign", 1, NULL, 's'},
  {"join", 1, NULL, 'j'},
  {"input", 1, NULL, 'i'},
  {"output", 1, NULL, 'o'},
  {"check", 1, NULL, 'c'},
  {"help", 0, NULL, 'h'},
  {"verbose", 0, NULL, 'v'},
};
int g10_errors_seen;
/* Description of short options */

static const char *const short_options = "s:j:i:o:c:hv";

/* Usage summary text */

static const char *const usage_help =
  "Usage: %s [ options ]\n"
  "Options:\n"
  "  -s,  --sign FILE               Sign an input file using partial key contained\n"
  "                                   in FILE. Input file specified in input option.\n"
  "  -j,  --join FILE               Join partial signed file. FILE contains list\n"
  "                                   of file name to be joined\n"
  "  -i,  --input FILE              Input file to be partially signed or checked.\n"
  "  -o,  --output FILE             Output file for partial signature.\n"
  "  -c,  --check FILE              FILE contains public key and input to be checked\n"
  "                                   must be specified in input option.\n"
  "  -h,  --help                    Print this information text.\n"
  "  -v,  --verbose                 Working in verbose mode.\n";


/* Global variables definition */

int verbose = 0;
uint32_t list[MAXSPLIT];
char *filelist[MAXSPLIT];
int num;

print_help (int err, const char *msg)
{
  if (msg)
    fprintf (err ? stderr : stdout, "\n%s", msg);
  fprintf (err ? stderr : stdout, usage_help, NAME);
  exit (err ? 1 : 0);
}

/*
 * Helper to hash some parts from the signature
 */
static void
hash_sigversion_to_magic (MD_HANDLE md, const PKT_signature * sig)
{
  if (sig->version >= 4)
    md_putc (md, sig->version);
  md_putc (md, sig->sig_class);
  if (sig->version < 4)
    {
      u32 a = sig->timestamp;
      md_putc (md, (a >> 24) & 0xff);
      md_putc (md, (a >> 16) & 0xff);
      md_putc (md, (a >> 8) & 0xff);
      md_putc (md, a & 0xff);
    }
  else
    {
      byte buf[6];
      size_t n;

      md_putc (md, sig->pubkey_algo);
      md_putc (md, sig->digest_algo);
      if (sig->hashed)
        {
          n = sig->hashed->len;
          md_putc (md, (n >> 8));
          md_putc (md, n);
          md_write (md, sig->hashed->data, n);
          n += 6;
        }
      else
        {
          md_putc (md, 0);      /* always hash the length of the subpacket */
          md_putc (md, 0);
          n = 6;
        }
      /* add some magic */
      buf[0] = sig->version;
      buf[1] = 0xff;
      buf[2] = n >> 24;         /* hmmm, n is only 16 bit, so this is always 0 */
      buf[3] = n >> 16;
      buf[4] = n >> 8;
      buf[5] = n;
      md_write (md, buf, 6);
    }
}


int
systemsign_parse_file (char *filename)
{
  FILE *inp = NULL;
  char file[40];
  char addr[16];
  int res;
  int err = 0;
  int i = 0;
  int n;
  STRLIST tmp;
  struct in_addr temp;

  if (!(inp = fopen (filename, "r")))
    return 1;

  do
    {
      res = fscanf (inp, "%40s %16s", file, addr);
      if (res != 2)
        break;
      /* Translate into unsigned long int */

      if (!inet_aton (addr, &temp))
        {
          err = 1;
          break;
        }

      list[i] = temp.s_addr;
      filelist[i] = (char *) strdup (file);
      i++;
    }
  while (!feof (inp) && (res == 2));

  if (err)
    {

      for (n = 0; n < i; n++)
        m_free (filelist[n]);

      return 1;
    }

  num = i;

  if (verbose)
    for (n = 0; n < num; n++)
      {
        printf ("File %u: %s    Address %u: %x\n", n, filelist[n], n,
                list[n]);
      }

  fclose (inp);
  return 0;
}

PKT_signature *
systemsign_get_signature (char *filename, IOBUF data)
{
  IOBUF inp = NULL;
  armor_filter_context_t afx;

  PKT_signature *sig = NULL;
  int n, i;


  /*open input line */
  if (!(inp = iobuf_open (filename)))
    {
      printf ("Error opening file\n");
      return sig;
    }

/* prepare armor filter */
  memset (&afx, 0, sizeof afx);
  iobuf_push_filter (inp, armor_filter, &afx);

  sig = proc_find_signature_packets (inp, data);

  iobuf_close (inp);
  return sig;
}



void
systemsign_join ()
{
  int n, j;
  int i = 0;
  IOBUF pubbuf = NULL;
  PACKET *pkt = m_alloc (sizeof *pkt);
  PKT_public_key *pk;
  PKT_signature *sig[MAXSPLIT] = { NULL };
  PKT_signature *ownsig = NULL;
  MPI base[MAXSPLIT] = { NULL };
  MPI res = NULL;
  IOBUF inp = NULL;
  IOBUF out = NULL;
  MD_HANDLE textmd = NULL;
  MPI frame;
  IOBUF full = NULL;
  PACKET *newpkt = m_alloc (sizeof *newpkt);
  int rc;
  armor_filter_context_t afx;
  IOBUF data[MAXSPLIT] = { NULL };
  FILE *outfile;
  char *buf;



  /* prepare public key file */
  if (!(pubbuf = iobuf_open ("public.key")))
    {
      m_free (pkt);
      return;
    }

  /* Initialize packet and parse it */
  init_packet (pkt);
  if (parse_packet (pubbuf, pkt))
    {
      goto leave;
    }

  if (pkt->pkttype != PKT_PUBLIC_KEY)
    goto leave;

  pk = pkt->pkt.public_key;

  /* Read file and find signature */
  for (i = 0; i < num; i++)
    {
      /* get signature data from file */
      data[i] = iobuf_temp ();
      sig[i] = systemsign_get_signature (filelist[i], data[i]);
      if (!sig[i])
        goto leave;

      /* copy hash data to base array */
      base[i] = mpi_copy (sig[i]->data[0]);
      printf ("base[%d]: ", i);
      mpi_print (stdout, base[i], 1);
      printf ("\n");
      printf ("Adrress ke %d: %x\n", i, list[i]);
    }

  /* Prepare our own signature to compare */
  /**** This is only for temporary use ****/
  out = iobuf_create ("output.gpg");

  /* Write header of output file */
  iobuf_writestr (out, "-----BEGIN PGP SIGNED MESSAGE-----" LF);
  iobuf_writestr (out, "Hash: ");
  iobuf_writestr (out, "SHA1" LF LF);

  /* Calculate message digest of input file and write text to output */
  textmd = md_open (0, 0);
  md_enable (textmd, DIGEST_ALGO_SHA1);
  /* we should not use data from what we receive to compare, because
   * we know what they should sign anyway.
   */
  copy_clearsig_text (out, data[0], textmd, !opt.not_dash_escaped,
                      opt.escape_from, 0);

    /*********** end here **************/

  /* copying everything from one of the signature */

  ownsig = (PKT_signature *) m_alloc_clear (sizeof *ownsig);
  memcpy (ownsig, sig[0], sizeof *ownsig);

  if (ownsig->version >= 4)
    build_sig_subpkt_from_sig (ownsig);

  hash_sigversion_to_magic (textmd, ownsig);
  md_final (textmd);
  frame = encode_md_value (ownsig->pubkey_algo, textmd,
                           ownsig->digest_algo, mpi_get_nbits (pk->pkey[0]),
                           0);
  printf ("frame: ", i);
  mpi_print (stdout, frame, 1);
  printf ("\n");
  md_close (textmd);
  iobuf_close (inp);


  /* only test */
  //   printf ("Hasil dari perhitungan kita : ");mpi_print (stdout, frame, 1); printf ("\n");
  //hash_sigversion_to_magic (newmd[0], ownsig);
  //md_final (newmd[0]);
  //frame = encode_md_value (ownsig->pubkey_algo, newmd[0],
  //                        ownsig->digest_algo, mpi_get_nbits(pk->pkey[0]), 0);

  //printf ("Hasil dari perhitungan kita : ");mpi_print (stdout, frame, 1); printf ("\n");
  //exit (0);
  /* Now we are ready to compare and get signature */
  res = (MPI) interpolate (base, pk, frame, list, num);

  if (res)
    {
      /* prepare armor filter */
      memset (&afx, 0, sizeof afx);
      afx.what = 2;
      iobuf_push_filter (out, armor_filter, &afx);

      /* prepare output packet */
      init_packet (newpkt);

      /* we get our signature in res, put it in signature packet */
      ownsig->data[0] = res;
      newpkt->pkttype = PKT_SIGNATURE;
      newpkt->pkt.signature = ownsig;
      rc = build_packet (out, newpkt);
    }
  else
    printf ("error getting certificate\n");
  printf ("finish writing\n");

leave:
  iobuf_close (out);
  for (n = 0; n < i; n++)
    {
      m_free (data[i]);
      free_seckey_enc (sig[n]);
    }
  iobuf_close (pubbuf);
  free_packet (pkt);
  free_packet (newpkt);
}

int
systemsign_sign (char *secfile, char *input, char *output)
{
  armor_filter_context_t afx;
  PACKET *pkt = m_alloc (sizeof *pkt);
  PKT_secret_key *sk;
  IOBUF inp = NULL;
  IOBUF out = NULL;

  IOBUF secbuf = NULL;
  MD_HANDLE textmd = NULL;
  u32 timestamp = 0, duration = 0;
  int i, n;
  int rc = 0;



  /* prepare input file */
  if (!(inp = iobuf_open (input)))
    {
      m_free (pkt);
      rc = 1;
      return rc;
    }

  /* prepare secret key file */
  if (!(secbuf = iobuf_open (secfile)))
    {
      m_free (pkt);
      iobuf_close (inp);
      rc = 2;
      return rc;
    }

  /* prepare output file */
  if (!(out = iobuf_create (output)))
    {
      m_free (pkt);
      iobuf_close (inp);
      iobuf_close (secbuf);
      rc = 3;
      return rc;
    }

  /* prepare armor filter */
  memset (&afx, 0, sizeof afx);

  /* Initialize packet and parse it */
  init_packet (pkt);
  if (parse_packet (secbuf, pkt))
    {
      rc = 4;
      goto leave;
    }

  if (pkt->pkttype == PKT_SECRET_KEY)
    {
      sk = pkt->pkt.secret_key;

      /* Write header of output file */
      iobuf_writestr (out, "-----BEGIN PGP SIGNED MESSAGE-----" LF);
      iobuf_writestr (out, "Hash: ");
      iobuf_writestr (out, "SHA1" LF LF);

      /* Calculate message digest of input file and write text to output */
      textmd = md_open (0, 0);
      md_enable (textmd, DIGEST_ALGO_SHA1);
      copy_clearsig_text (out, inp, textmd, !opt.not_dash_escaped,
                          opt.escape_from, 0);

      /* Use armor for output from now on */
      afx.what = 2;
      iobuf_push_filter (out, armor_filter, &afx);

      /* we can not check for this one, because the private key
       * is only partial one i.e. no public key for that */
      opt.no_sig_create_check = 1;
      rc = write_one_signature (sk, out, textmd, 0x01,
                                timestamp, duration, 'C');
      opt.no_sig_create_check = 0;
    }
  else
    rc = 5;



leave:
  free_packet (pkt);
  iobuf_close (inp);
  iobuf_close (out);
  iobuf_close (secbuf);
  md_close (textmd);
  return rc;
}

int
main (int argc, char **argv)
{
  int next_option;
  int rc = 0;
  int cmd = 0;

  char *input = NULL;
  char *output = NULL;
  char *filename = NULL;

  /* initialize gpg environment */
  init ("systemsign");

  /* There is no default action here */
  if (argc < 2)
    print_help (0, NULL);

  /* Parse all options first */
  do
    {
      next_option =
        getopt_long (argc, argv, short_options, long_options, NULL);
      switch (next_option)
        {
        case 's':
          {
            if (cmd)
              {
                rc = 1;
                break;
              }

            cmd = CMDSIGN;
            filename = (char *) strdup (optarg);
          }
          break;

        case 'j':
          {
            if (cmd)
              {
                rc = 1;
                break;
              }

            cmd = CMDJOIN;
            filename = (char *) strdup (optarg);
          }
          break;

        case 'i':
          {
            input = (char *) strdup (optarg);
          }
          break;

        case 'o':
          {
            output = (char *) strdup (optarg);
          }
          break;

        case 'c':
          {
            if (cmd)
              {
                rc = 1;
                break;
              }

            cmd = CMDCHECK;
            filename = (char *) strdup (optarg);
          }
          break;

        case 'h':
          /* User specified -h or --help */
          print_help (0, NULL);

        case 'v':
          /* User specified -v or --verbose */
          verbose = 1;
          break;

        case '?':
          /* User specified an unrecognized option. */
          print_help (1, "Error: unspecified option\n");

        case -1:
          /* Done with parsing options. */
          break;

        default:
          /* User specified unknown option, give them help with error */
          print_help (1, "Error: unspecified option\n");
        }
    }
  while (next_option != -1 && !rc);

  /* user specified two or more command */
  if (rc)
    {
      print_help (1, "You can only specify one command\n"
                  "[ --sign | --join | --check ]\n");
    }

  /* We need no more options. Issue an error if the user specified any */
  if (optind != argc)
    print_help (1, "Error: unspecified option\n");

  /* Initialize secure memory */
  secmem_init (16384);

  if (cmd == CMDSIGN)
    {
      if (!input)
        print_help (1, "You must specify file to be signed\n"
                    "in [ --input | -i ] option\n");
      if (!output)
        {
          printf ("You didn't specifiy output file.\n"
                  "Using %s as output file\n", DEFOUT DEFEXT);
          output = (char *) strdup (DEFOUT DEFEXT);
        }
      if (rc = systemsign_sign (filename, input, output))
        {
          if (rc == 1)
            log_error ("Can't open input file\n");
          else if (rc == 2)
            log_error ("Can't open secret key file\n");
          else if (rc == 3)
            log_error ("Can't open output key file\n");
          else if (rc == 4)
            log_error ("Error parsing file\n");
          else if (rc == 5)
            log_error ("Can not find secret key in secret key file\n");
          else
            log_error ("Error writing signature\n");
        }
    }
  else if (cmd == CMDJOIN)
    {
      if (!output)
        {
          printf ("You didn't specifiy output file.\n"
                  "Using %s as output file\n", DEFOUT DEFEXT);
          output = (char *) strdup (DEFOUT DEFEXT);
        }
      if (rc = systemsign_parse_file (filename))
        {
          printf ("Error parsing file\n");
          goto leave;
        }
      systemsign_join ();
    }
  else if (cmd == CMDCHECK)
    {
      if (!input)
        print_help (1, "You must specify file to be signed\n"
                    "in [ --input | -i ] option\n");
    }

leave:
  secmem_term ();
  m_free (input);
  m_free (output);
  m_free (filename);
  exit (0);
}
