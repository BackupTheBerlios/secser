#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "globals.h"
#include "util.h"
#include "iobuf.h"
#include "memory.h"
#include "msg.h"
#include "main.h"
#include "options.h"
#include "systemsign.h"

#define CRLF "\r\n"

/* note we hard coded the ip address and port of via message here,
 * if you want to change the port of the runnig server, please 
 * change it as well here. Also make a change in process_remove_via
 */
#define VIA_MSG "Via: SIP/2.0/UDP 127.0.0.1:4050;branch=z9hG4bK6"
#define VIA_LEN 47
#define VIA_SEP "."

int
process_sign_package (struct sip_msg *msg, STRLIST locusr, STRLIST recipient,
                      int orig)
{
  char *tmpfile;
  FILE *tmp = NULL;
  size_t length;
  char *buf;

/* Prepare a new file name */
  get_secure_name (&tmpfile);

/* sign the file */
  if (orig)
    {
      if (clearsign_file (msg->orig, msg->len, locusr, tmpfile))
        {
          goto error;
        }
    }
  else
    {
      if (clearsign_file (msg->buf, msg->buflen, locusr, tmpfile))
        {
          goto error;
        }
    }

/* read resulting file */
  tmp = fopen (tmpfile, "r");
  if (!tmp)
    {
      log_error ("something wrong with our package");
      goto error;
    }
  fseek (tmp, 0, SEEK_END);
  length = ftell (tmp);
  rewind (tmp);

  if (orig)
    {
      if ((length + msg->hdr_len + 2) > MAX_BUF)
        m_realloc (msg->buf, length + msg->hdr_len + 2);
      memcpy (msg->buf, msg->orig, msg->hdr_len);
      msg->buf[msg->hdr_len] = msg->buf[msg->hdr_len + 1] = '\n';
      buf = (msg->buf) + msg->hdr_len + 2;
      msg->buflen = msg->hdr_len + length + 2;
    }
  else
    {
      /* we already have header in buf, dont rewrite it */
      if ((length + msg->hdr_len2) > MAX_BUF)
        m_realloc (msg->buf, length + msg->hdr_len2);
      buf = (msg->buf) + msg->hdr_len2;
      msg->buflen = msg->hdr_len2 + length;
    }
  fread (buf, 1, length, tmp);

  /* close and delete temp file */
  fclose (tmp);
  unlink (tmpfile);
  return 0;

error:
  if (tmp)
    {
      fclose (tmp);
      unlink (tmpfile);
    }
  m_free (tmpfile);
  return 1;
}

int
process_verify_package (struct sip_msg *msg)
{
  char *tmpfile;
  char *tmpout;
  FILE *tmp = NULL;
  FILE *out = NULL;
  size_t length;
  char *buf;
  int rc;

/* Prepare a new file name */
  get_secure_name (&tmpfile);
  get_secure_name (&tmpout);

/* create tmp file */
  tmp = fopen (tmpfile, "w");
  if (!tmp)
    {
      log_error ("something wrong with our package\n");
      goto error;
    }
  fwrite (msg->body, 1, msg->body_len, tmp);
  fclose (tmp);

  /* set the output to temporary file */
  opt.outfile = tmpout;

  /* verify file */
  if (!(rc = decrypt_message (tmpfile)))
    {

      /* open and read the output */
      out = fopen (tmpout, "r");
      if (!out)
        {
          log_error ("Error reading output file\n");
          goto error;
        }
      fseek (out, 0, SEEK_END);
      length = ftell (out);
      rewind (out);
      if (length > MAX_BUF)
        m_realloc (msg->buf, length);
      fread (msg->buf, 1, length, out);
      fclose (out);
      msg->buflen = length;

      /* close and delete temp file */
      unlink (tmpfile);
      unlink (tmpout);
      return 0;
    }
  else
    {
      unlink (tmpfile);
      unlink (tmpout);
      return rc;
    }

error:
  return 1;
}

int
process_create_reg_body (char **buffer, STRLIST locusr, STRLIST recipient,
                         unsigned *len)
{
  char *tmpout;
  FILE *out = NULL;
  char *buf = NULL;
  STRLIST tmplist;
  char *usr = NULL;
  char *addr = NULL;
  uint16_t port;
  char *result;
  int length;
  char *body;
  int i;

  /* Prepare a new file name */
  get_secure_name (&tmpout);

  /* set the output file */
  opt.outfile = tmpout;
  opt.armor = 1;
  opt.no_armor = 0;

  if (export_pubkeys (locusr, 0))
    {
      log_error ("User can not be found\n");
      goto error;
    }


  /* get the user, we hope now it is only one user in the list.
   * We need to improve this, either there is exactly only one user
   * or check which users has been found in the database */
  tmplist = locusr;
  if (tmplist && tmplist->d)
    usr = tmplist->d;


  /* get the listening address, only the first address if listening to all */


  /* we dont want to send 127.0.0.1 */
  i = 0;
  do
    {
      addr = sock_info[i].name;
      i++;
    }
  while ((!strcmp (addr, "127.0.0.1") || !strcmp (addr, "255.255.255.255")) &&
         (i < sock_no));
  if (!usr || !addr)
    goto error;
  /* get port number */
  port = sock_info[0].port_no;

  /* open and read output file */
  out = fopen (tmpout, "r");
  if (!out)
    {
      log_error ("Can not open out file\n");
      goto error;
    }
  fseek (out, 0, SEEK_END);
  length = ftell (out);
  rewind (out);
  buf = m_alloc (length);
  if (!buf)
    {
      log_error ("Not enough memory\n");
      goto error;
    }
  fread (buf, 1, length, out);
  fclose (out);


  unlink (tmpout);

  /* syntax :
   * user: username
   * address: ip number
   * port: port number
   * public key*/
/*                  user: name         \n  address: addr        \n   port: no  \n */
  length =
    length + (6 + strlen (usr) + 1) + (9 + strlen (addr) + 1) + (6 + 6 + 1) +
    1;
  body = m_alloc (length);
  if ((length = snprintf (body, length, "user: %s\n"
                          "address: %s\n"
                          "port: %u\n" "%s", usr, addr, port, buf)) == -1)
    {
      log_error ("Not enough buffer\n");
      printf ("not enough buffer\n");
      goto error;
    }
  *buffer = body;
  *len = length;

  m_free (buf);

  return 0;

error:
  unlink (tmpout);
  if (out)
    {
      fclose (out);
    }
  m_free (buf);
  return 1;
}

int
process_create_header (struct sip_msg *msg, int ev)
{

  if (!msg->from)
    return 1;
  // We might need to add message ID later on 
  memset (msg->buf, 0, MAX_BUF);

  /* if we are here, we can be sure that we create a new message
   * then we put header len in hdr_len2
   */
  /*       "CERT+CRLF" "Event: " */
  msg->hdr_len2 = 6 + 7;
  strcat (msg->buf, "CERT" CRLF);
  strcat (msg->buf, "Event: ");
  switch (ev)
    {
    case EV_SIG:
      {
        msg->hdr_len2 += EV_SIG_LEN;
        strcat (msg->buf, EV_SIG_STR);
      }
      break;

    case EV_SIGREP:
      {
        msg->hdr_len2 += (strlen (msg->to) + EV_SIGREP_LEN + 2);
        strcat (msg->buf, EV_SIGREP_STR);
        strcat (msg->buf, msg->to);
        strcat (msg->buf, CRLF);
      }
      break;

    case EV_PART:
      {
        msg->hdr_len2 += EV_PART_LEN;
        strcat (msg->buf, EV_PART_STR);
      }
      break;

    case EV_PART_OK:
      {
        msg->hdr_len2 += EV_PART_OK_LEN;
        strcat (msg->buf, EV_PART_OK_STR);
      }
      break;

    case EV_PART_LIST:
      {
        msg->hdr_len2 += EV_PART_LIST_LEN;
        strcat (msg->buf, EV_PART_LIST_STR);
      }
      break;

    case EV_PART_ADD:
      {
        msg->hdr_len2 += (strlen (msg->req) + EV_PART_ADD_LEN);
        strcat (msg->buf, EV_PART_ADD_STR);
        strcat (msg->buf, msg->req);
      }
      break;

    case EV_PART_KEY:
      {
        msg->hdr_len2 += (strlen (msg->to) + EV_PART_KEY_LEN + 2);
        strcat (msg->buf, EV_PART_KEY_STR);
        strcat (msg->buf, msg->to);
        strcat (msg->buf, CRLF);
      }
      break;

    case EV_ADDR:
      {
        msg->hdr_len2 += EV_ADDR_LEN;
        strcat (msg->buf, EV_ADDR_STR);
      }
      break;
    }
  strcat (msg->buf, msg->from);
  strcat (msg->buf, CRLF CRLF);
  msg->hdr_len2 += (strlen (msg->from) + 4);
  msg->buflen = msg->hdr_len2;
  return 0;
}

int
process_reg_response (struct sip_msg *msg, STRLIST locusr, STRLIST recipient)
{
  unsigned int addlen;
  char *buffer = NULL;
  char *tmp = NULL;
  FILE *fcert = NULL;
  unsigned int length;
  STRLIST tmplist;
  unsigned int hdr_len;

  fcert = fopen (ADHOC_HOMEDIR DIRSEP_S CERTFILE, "r");
  if (fcert)
    {
      /* we have our certificate ready here, we just have to attach 
       * to our header message
       */
      length = get_file_length (fcert);
      /* free this message to create a new one */
      if ((length + msg->hdr_len + 2) > MAX_BUF)
        m_realloc (msg->buf, length + msg->hdr_len + 2);
      memcpy (msg->buf, msg->orig, msg->hdr_len);
      msg->buf[msg->hdr_len] = msg->buf[msg->hdr_len + 1] = '\n';
      tmp = (msg->buf) + msg->hdr_len + 2;
      fread (tmp, 1, length, fcert);

      fclose (fcert);
      msg->buflen = msg->hdr_len + 2 + length;
      msg->buf[msg->buflen] = '\0';
      return 0;
    }
  else
    {
      /* we dont have certificate yet, so we need to create a message 
       * contains our data with our own public key
       */

      if (process_create_reg_body (&buffer, locusr, recipient, &length))
        return 1;

      /* We change the header here to CERT header  */
      if (process_create_header (msg, EV_SIG))
        {
          m_free (buffer);
          return 1;
        }

      /* prepare the message to be signed */
      if ((length + msg->hdr_len2) > MAX_BUF)
        m_realloc (msg->buf, length + msg->hdr_len + 2);
      /* we have the header in msg->buf already, so just copy the body
       * for now
       */
      tmp = (msg->buf) + msg->hdr_len2;
      memcpy (tmp, buffer, length);
      m_free (buffer);
      msg->buflen = length + msg->hdr_len2;
      /* next step is to sign this message with our own key */
      if (process_sign_package (msg, locusr, recipient, 0))
        {
          printf (" Error while signing...\n");
          return 1;
        }
      return 0;
    }
  return 1;
}




int
process_verify_with_system (struct sip_msg *msg)
{
  char *tmpfile;
  FILE *tmp = NULL;
  IOBUF pubbuf = NULL;
  PACKET *pkt = m_alloc (sizeof *pkt);
  PKT_public_key *pk;
  PKT_signature *sig = NULL;
  MD_HANDLE textmd = NULL;
  MPI frame = NULL;
  int rc;
  IOBUF data = NULL;
  IOBUF temp = NULL;
  FILE *outfile;
  char *buf;
  char c;
  int i;


  /* Prepare a new file name */
  get_secure_name (&tmpfile);

  /* create tmp file */
  tmp = fopen (tmpfile, "w");
  if (!tmp)
    {
      log_error ("can not create temporary file\n");
      goto leave;
    }
  fwrite (msg->body, 1, msg->body_len, tmp);
  fclose (tmp);

  /* Get signature data */
  data = iobuf_temp ();
  temp = iobuf_temp ();
  sig = systemsign_get_signature (tmpfile, data);
  if (!sig)
    {
      unlink (tmpfile);
      goto leave;
    }
  unlink (tmpfile);

  /* Calculate our own messge digest */
  textmd = md_open (0, 0);
  md_enable (textmd, DIGEST_ALGO_SHA1);

  /* fixme: find another way to do it, it is stupid to use temp just as to make it work */
  copy_clearsig_text (temp, data, textmd, !opt.not_dash_escaped,
                      opt.escape_from, 0);
  iobuf_close (temp);
  systemsign_sigversion_to_magic (textmd, sig);
  md_final (textmd);

  /* prepare public key file */
  if (!(pubbuf = iobuf_open (ADHOC_HOMEDIR DIRSEP_S PUBFILE)))
    {
      goto leave;
    }
  /* Initialize packet and parse packet file */
  init_packet (pkt);
  if (parse_packet (pubbuf, pkt))
    {
      iobuf_close (pubbuf);
      goto leave;
    }

  iobuf_close (pubbuf);
  if (pkt->pkttype != PKT_PUBLIC_KEY)
    goto leave;
  pk = pkt->pkt.public_key;

  frame = encode_md_value (pk->pubkey_algo, textmd,
                           sig->digest_algo, mpi_get_nbits (pk->pkey[0]), 0);
  md_close (textmd);

  /* verify signature */
  if (pubkey_verify (pk->pubkey_algo, frame, sig->data, pk->pkey, NULL, NULL))
    goto leave;

  if (data->d.len > MAX_BUF)
    msg->buf = (char *) realloc (data->d.len);
  iobuf_temp_to_buffer (data, msg->buf, data->d.len);
  msg->buflen = data->d.len;
  return 0;
leave:
  free_packet (pkt);
  free_seckey_enc (sig);
  iobuf_close (data);
  return 1;
}


int
process_reg_body (struct reg_body *regbody)
{
  char *tmpfile;
  FILE *tmp = NULL;
  IOBUF pkbuf = NULL;
  int rc;

  /* Prepare a new file name */
  get_secure_name (&tmpfile);

  tmp = fopen (tmpfile, "w");
  if (!tmp)
    return -1;

  fwrite (regbody->public_key, 1, regbody->pk_len, tmp);
  fclose (tmp);

  if (!(pkbuf = iobuf_open (tmpfile)))
    {
      unlink (tmpfile);
      return -1;
    }

  /* import key to key database and delete file */
  rc = import_keys_stream (pkbuf, 0, NULL, opt.import_options);
  iobuf_close (pkbuf);
  unlink (tmpfile);
  if (rc)
    return -1;

  /* adding route if everything is ok */
  rc = route_add (regbody);
  return rc;
}

void
process_generate_adder (MPI * adder, int num)
{
  int i;
  char *p;

  /* Generate random number num times */
  for (i = 0; i < num; i++)
    {

      /* We are using FBITS bits for adder */
      adder[i] =
        mpi_alloc ((FBITS + BITS_PER_MPI_LIMB - 1) / BITS_PER_MPI_LIMB);
      p = get_random_bits (FBITS, 0, 0);
      mpi_set_buffer (adder[i], p, (FBITS + 7) / 8, 0);
    }
}

int
process_remove_via (struct sip_msg *msg)
{
  char via[256];
  size_t len;

  if (!msg->via1)
    {
      log_error ("No via found in the message\n");
      return 1;
    }
  /* we should remove first via and second via will be our next hop */
  if (!msg->via2)
    {
      log_error ("No second via found in the message\n");
      return 1;
    }
  len = (msg->via2 - msg->via1);
  if (len > 256)
    {
      log_error ("Via message to long\n");
      return 1;
    }

  memcpy (via, msg->via1, len);
  via[len] = '\0';
/* make a change here if you change the port or ip address of the server */
  if (!strstr (via, "127.0.0.1:4050"))
    {
      log_error ("Can not find our address in first via\n");
      return 1;
    }
  /* we must change msg->orig instead of msg->buf, because
   * outgoing reply and outgoing other message request sign msg->orig.
   */
  memmove (msg->orig + (msg->via1 - msg->buf),
           msg->orig + (msg->via2 - msg->buf),
           msg->len - (msg->via2 - msg->buf));
  msg->len -= len;
  msg->hdr_len -= len;
  return 0;
}

int
process_insert_via (struct sip_msg *msg)
{
  char via[256] = { 0 };
  size_t len;

  if (!msg->via1)
    {
      log_error ("No via found in the message\n");
      return 1;
    }

  /* create branch here and add len of branch to len */
  len = VIA_LEN;

  memcpy (via, VIA_MSG, len);
  strcat (via, ".0\r\n");
  len += 4;

  memmove (msg->via1 + len, msg->via1, msg->len - (msg->via1 - msg->buf));
  memcpy (msg->via1, via, len);
  msg->buflen += len;
  msg->hdr_len2 += len;
  return 0;
}
