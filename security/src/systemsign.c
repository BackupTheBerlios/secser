#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>

#include "util.h"
#include "iobuf.h"
#include "mpi.h"
#include "memory.h"
#include "options.h"
#include "packet.h"
#include "globals.h"
#include "systemsign.h"
#include "semaphore.h"


#define LF "\n"



/*
 * Helper to hash some parts from the signature
 */
void
systemsign_sigversion_to_magic (MD_HANDLE md, const PKT_signature * sig)
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


int
systemsign_join (char *buf, unsigned buflen, uint32_t remoteaddr)
{
  int n, j;
  int i = 0;
  IOBUF pubbuf = NULL;
  PACKET *pkt = m_alloc (sizeof (*pkt));
  PKT_public_key *pk;
  PKT_signature *sig = NULL;
  PKT_signature *ownsig = NULL;
  MPI base[MAXSPLIT] = { NULL };
  uint32_t addrlist[MAXSPLIT];
  MPI res = NULL;
  IOBUF inp = NULL;
  IOBUF out = NULL;
  MD_HANDLE textmd = NULL;
  MPI frame;
  IOBUF full = NULL;
  PACKET *newpkt = m_alloc (sizeof (*pkt));
  int rc;
  armor_filter_context_t afx;
  IOBUF data = NULL;
  FILE *outfile;
  IOBUF tmpcert = NULL;

  byte num = 0;
  size_t length = 0;
  char *signame;
  FILE *sigfd = NULL;
  size_t mpilen;
  size_t tmplen;


  /* create temporary file */
  get_secure_name (&signame);
  sigfd = fopen (signame, "w");
  if (!sigfd)
    {
      return 1;
    }
  fwrite (buf, 1, buflen, sigfd);
  fclose (sigfd);


  /* get signature data from file */
  data = iobuf_temp ();
  sig = systemsign_get_signature (signame, data);
  unlink (signame);
  m_free (signame);
  if (!sig)
    {
      rc = 1;
      goto leave;
    }
  semaphore_wait (semapid, SEMTMPCERT);
  tmpcert = iobuf_openrw (ADHOC_HOMEDIR DIRSEP_S TMPCERTFILE);
  /* we must have .tmpcert file if we come to here */
  if (!tmpcert)
    {
      semaphore_post (semapid, SEMTMPCERT);
      rc = 1;
      goto leave;
    }

  /* copy hash data to base array */
  base[0] = mpi_copy (sig->data[0]);
  addrlist[0] = remoteaddr;

  length = iobuf_get_filelength (tmpcert);

  if (length)
    num = iobuf_readbyte (tmpcert);
  else
    num = 0;

  if (num < (NUMPART - 1))
    {
      for (i = 0; i < num; i++)
        {
          iobuf_read (tmpcert, (char *) &(addrlist[i]), 4);
          if (addrlist[i] == remoteaddr)
            {
              /* we have this address already */
              iobuf_close (tmpcert);
              free_packet (pkt);
              free_packet (newpkt);
              free_seckey_enc (sig);
              semaphore_post (semapid, SEMTMPCERT);
              return 1;
            }
          /* fixme: it is funny that we read it just to skip
           * until next address */
          base[i] = mpi_read (tmpcert, &mpilen, 0);
          mpi_free (base[i]);
        }
      num++;
      iobuf_seek (tmpcert, 0);
      iobuf_writebyte (tmpcert, num);
      iobuf_flush (tmpcert);
      if (!length)
        length = 1;
      iobuf_seek (tmpcert, length);
      iobuf_write (tmpcert, (char *) &remoteaddr, 4);
      mpi_write (tmpcert, base[0]);
      iobuf_close (tmpcert);
      free_packet (pkt);
      free_packet (newpkt);
      free_seckey_enc (sig);
      semaphore_post (semapid, SEMTMPCERT);
      return -1;
    }
  tmplen = length - 1;
  /* read list of base and address */
  for (i = 1; i < NUMPART; i++)
    {
      /* read address */
      iobuf_read (tmpcert, (char *) &(addrlist[i]), 4);
      tmplen -= 4;
      mpilen = tmplen;

      /* read mpi data of partial signature */
      base[i] = mpi_read (tmpcert, &mpilen, 0);
      tmplen -= mpilen;
    }
  iobuf_close (tmpcert);

  /* prepare public key file */
  if (!(pubbuf = iobuf_open (ADHOC_HOMEDIR DIRSEP_S PUBFILE)))
    {
      rc = 1;
      semaphore_post (semapid, SEMTMPCERT);
      goto leave;
    }

  /* Initialize packet and parse it */
  init_packet (pkt);
  if (parse_packet (pubbuf, pkt))
    {
      rc = 1;
      semaphore_post (semapid, SEMTMPCERT);
      goto leave;
    }
  if (pkt->pkttype != PKT_PUBLIC_KEY)
    {
      rc = 1;
      semaphore_post (semapid, SEMTMPCERT);
      goto leave;
    }
  pk = pkt->pkt.public_key;

  /* Prepare our own signature to compare */

  out = iobuf_create (ADHOC_HOMEDIR DIRSEP_S CERTFILE);

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
  copy_clearsig_text (out, data, textmd, !opt.not_dash_escaped,
                      opt.escape_from, 0);

  /* copying everything from one of the signature */
  ownsig = (PKT_signature *) m_alloc_clear (sizeof *ownsig);
  memcpy (ownsig, sig, sizeof *ownsig);

  if (ownsig->version >= 4)
    build_sig_subpkt_from_sig (ownsig);

  systemsign_sigversion_to_magic (textmd, ownsig);
  md_final (textmd);
  frame = encode_md_value (ownsig->pubkey_algo, textmd,
                           ownsig->digest_algo, mpi_get_nbits (pk->pkey[0]),
                           0);
  md_close (textmd);
  iobuf_close (inp);

  /* Now we are ready to compare and get signature */
  res = (MPI) interpolate (base, pk, frame, addrlist, NUMPART);

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
      if (!rc)
        {
          /* we have our certificate, so delete .tmpcert file
           * so no one will call this procedure anymore
           */
          unlink (ADHOC_HOMEDIR DIRSEP_S TMPCERTFILE);
          semaphore_post (semapid, SEMTMPCERT);
        }
    }
  else
    rc = 1;

leave:
  iobuf_close (out);
  for (i = 0; i < num; i++)
    mpi_free (base[i]);
  iobuf_close (data);
  iobuf_close (pubbuf);
  free_packet (pkt);
  free_packet (newpkt);
  free_seckey_enc (sig);
  if (rc)
    unlink (ADHOC_HOMEDIR DIRSEP_S CERTFILE);
  return rc;

}

int
systemsign_sign (char *output, char *inpbuf, unsigned length)
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



  /* prepare input buffer */
  if (!(inp = iobuf_temp_with_content (inpbuf, length)))
    {
      m_free (pkt);
      rc = 1;
      return rc;
    }

  /* prepare secret key file */
  if (!(secbuf = iobuf_open (ADHOC_HOMEDIR DIRSEP_S PARTFILE)))
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

  md_close (textmd);

leave:
  iobuf_close (out);
  free_packet (pkt);
  m_free (pkt);
  iobuf_close (inp);
  iobuf_close (secbuf);

  return rc;
}
