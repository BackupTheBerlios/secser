#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>


#include "globals.h"
#include "options.h"
#include "adhoc.h"
#include "util.h"
#include "iobuf.h"
#include "memory.h"
#include "msg.h"
#include "main.h"
#include "systemsign.h"
#include "udp_server.h"
#include "semaphore.h"

char dectab[256] = {            /* radix64 decoding table */
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, 64, -1, -1,
  -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};                              /* dectab[] */

unsigned
handle_radix64_decode (char **outbuff, char *inbuff, unsigned length)
{
  char d[4];
  char *cp = inbuff;
  char *b = m_alloc ((length + 3) / 4 * 3 + 1);
  long di = 0;
  char c;
  char *e = b + ((length + 3) / 4 * 3 + 1);
  char *p = b;

  while ((b < e) && ((c = *(cp++)) != 0))
    {
      if ((c = dectab[c]) >= 0)
        {
          d[di++] = c;
          if (di == 4)
            {
              b[0] = (d[0] << 2) | ((d[1] >> 4) & 0x3);
              b[1] = ((d[1] & 0xf) << 4) | ((d[2] >> 2) & 0xf);
              b[2] = ((d[2] & 0x3) << 6) | d[3];
              b += 3;
              if (d[3] == 64)
                b--;
              if (d[2] == 64)
                b--;
              di = 0;
            }
        }
    }

  if (di == 2)
    {
      b[0] = (d[0] << 2) | ((d[1] >> 4) & 0x3);
      b += 1;
    }
  else if (di == 3)
    {
      b[0] = (d[0] << 2) | ((d[1] >> 4) & 0x3);
      b[1] = ((d[1] & 0xf) << 4) | ((d[2] >> 2) & 0xf);
      b += 2;
    }
  *outbuff = p;
  return (b - *outbuff);
}

int
handle_incoming_reg (struct sip_msg *msg)
{
  int rc = 0;
  struct body_msg *body = NULL;
  struct reg_body *regbody = NULL;

  body = m_alloc (sizeof (*body));
  /* Verifying message with system public key */
  if (process_verify_with_system (msg))
    {
      log_error (" Can not verify body message \n");
      rc = -1;
      goto leave;
    }
  /* parsing message body to get route and key */
  if (parse_body (msg->buf, msg->buflen, body))
    {
      log_error ("Can not parse incoming register body\n");
      rc = -1;
      goto leave;
    }
  if (body->msg.regbody)
    regbody = body->msg.regbody;

  /* importing key and adding route */
  rc = process_reg_body (regbody);
  if (rc == 0)
    log_info ("route already there\n");
  else if (rc == 1)
    log_info ("adding new route to the route.txt file\n");
  else if (rc == 2)
    log_info ("route has been changed\n");
  else
    {
      ("Error happened when checking route\n");
      rc = -1;
    }

leave:
  if (regbody->user)
    m_free (regbody->user);
  if (regbody->ip)
    m_free (regbody->ip);
  if (regbody->public_key)
    m_free (regbody->public_key);
  m_free (regbody);
  m_free (body);
  return rc;
}

static int
handle_header (struct sip_msg *msg, STRLIST sender, STRLIST recipient,
               int type)
{
  STRLIST sender1 = NULL;
  STRLIST recipient1 = NULL;
  STRLIST tmplist, tmplist1;

  /* verify incoming reply message */
  if (process_verify_package (msg))
    {
      log_error ("Error verifying message\n");
      goto error;
    }
  log_info ("Message has been verified\n");

  /* we need to parse message header in the body again to compare
   * with the real header that we parse before
   */
  if (parse_msg (msg, &sender1, &recipient1))
    {
      /* something is wrong, free the message */
      log_error ("There is something wrong when parsing the message\n");
      goto error;
    }
  if (!(msg->type == MSG_CERT) || !(msg->evt == type))
    goto error;

  /* check sender */
  for (tmplist = sender, tmplist1 = sender1;
       tmplist && tmplist1;
       tmplist = tmplist->next, tmplist1 = tmplist1->next)
    {
      if (!(strcmp (tmplist->d, tmplist1->d) == 0))
        goto error;
    }
  if ((tmplist && !tmplist1) || (!tmplist && tmplist1))
    goto error;

  /* check receiver */
  for (tmplist = recipient, tmplist1 = recipient1;
       tmplist && tmplist1;
       tmplist = tmplist->next, tmplist1 = tmplist1->next)
    {
      if (!(strcmp (tmplist->d, tmplist1->d) == 0))
        goto error;
    }
  if ((tmplist && !tmplist1) || (!tmplist && tmplist1))
    goto error;

  /* no error happened */

  return 0;

error:

  free_strlist (recipient1);
  free_strlist (sender1);
  return 1;
}

int
handle_calc_newpart (char **data, MPI dividen, MPI * adder, int pos, int num)
{
  IOBUF secbuf;
  PACKET *pkt = m_alloc (sizeof *pkt);
  PKT_secret_key *sk;
  MPI newkey = mpi_alloc (0);
  char *buffer;
  size_t length;
  IOBUF out;
  char *outname;
  int i;
  FILE *fd;

  /* prepare secret key file */
  if (!(secbuf = iobuf_open (ADHOC_HOMEDIR DIRSEP_S PARTFILE)))
    {
      m_free (pkt);
      goto error;
    }

  /* Initialize packet and parse secret file */
  init_packet (pkt);
  if (parse_packet (secbuf, pkt))
    {
      goto error;
    }

  if (pkt->pkttype == PKT_SECRET_KEY)
    {
      sk = pkt->pkt.secret_key;
      mpi_mul (newkey, sk->skey[2], dividen);
      if ((num % 2) && (pos == (num / 2)))
        mpi_add (newkey, newkey, adder[num / 2]);
      else if (pos < (num / 2))
        for (i = 0; i < (num / 2 - pos); i++)
          {
            mpi_add (newkey, newkey, adder[i]);
          }
      else if (pos >= (num / 2))
        {
          if (num % 2)
            for (i = 0; i < (pos - num / 2); i++)
              {
                mpi_sub (newkey, newkey, adder[i]);
              }
          else
            for (i = 0; i < (pos - num / 2 + 1); i++)
              {
                mpi_sub (newkey, newkey, adder[i]);
              }
        }
      if ((num % 2) && (pos == 0))
        mpi_sub (newkey, newkey, adder[num / 2]);

      mpi_free (sk->skey[2]);
      sk->skey[2] = newkey;

      /* Prepare a new file name */
      get_secure_name (&outname);

      /* prepare iobuf */
      out = iobuf_create (outname);
      if (!out)
        {
          goto error;
        }

      if (build_packet (out, pkt))
        {
          iobuf_cancel (out);
          goto error;
        }
      iobuf_close (out);
      fd = fopen (outname, "r");
      length = get_file_length (fd);
      buffer = m_alloc (length);
      fread (buffer, 1, length, fd);
      fclose (fd);
      unlink (outname);
      m_free (outname);
      *data = make_radix64_string (buffer, length);
      free_packet (pkt);
      m_free (buffer);
      return 0;
    }
error:
  free_packet (pkt);
  m_free (buffer);
  return 1;
}


int
handle_create_key (char **key, size_t * keylen, uint32_t * id, byte num)
{
  PACKET *pkt[MAXSPLIT];
  PKT_secret_key *sk;
  int i, j;
  IOBUF temp;
  MPI d[MAXSPLIT];
  MPI divisor;
  MPI res = mpi_alloc (0);
  MPI newd = mpi_alloc (0);
  IOBUF out;

  for (i = 0; i < num; i++)
    {
      temp = iobuf_temp_with_content (key[i], keylen[i]);
      pkt[i] = m_alloc (sizeof *pkt[i]);
      init_packet (pkt[i]);
      if (parse_packet (temp, pkt[i]))
        goto leave;

      if (pkt[i]->pkttype != PKT_SECRET_KEY)
        goto leave;
      sk = pkt[i]->pkt.secret_key;
      d[i] = sk->skey[2];
    }

  i--;
  divisor = (MPI) calculate_divisor1 (id, num);
  for (j = 0; j < num; j++)
    mpi_add (res, res, d[i]);
  mpi_fdiv_q (newd, res, divisor);

  m_free (sk->skey[2]);
  sk->skey[2] = newd;
  out = iobuf_create (ADHOC_HOMEDIR DIRSEP_S PARTFILE);
  if (build_packet (out, pkt[i]))
    {
      iobuf_cancel (out);
      goto leave;
    }
  iobuf_close (out);
  for (j = 0; j < num; j++)
    free_packet (pkt[j]);
  mpi_free (res);
  return 0;
leave:
  for (j = 0; j <= i; j++)
    free_packet (pkt[j]);
  mpi_free (res);
  return 1;
}

int
handle_parse_adderfile (char *reqsip, byte * pos, uint32_t * dis,
                        uint32_t requestor, uint32_t remoteaddr)
{
  FILE *fd;
  char c;
  uint32_t xi;
  size_t length;
  char *data, *tmp, *tmp1, *end;
  unsigned cnt;
  char reqaddr[100];
  int found;
  int i;

  semaphore_wait (semapid, SEMADD);
  fd = fopen (ADHOC_HOMEDIR DIRSEP_S ADDERFILE, "r");
  if (!fd)
    return 1;
  length = get_file_length (fd);
  data = m_alloc (length);
  tmp = tmp1 = data;
  end = tmp + length;
  fread (data, 1, length, fd);
  fclose (fd);
  found = 0;
  while (tmp < end)
    {
      cnt = 0;
      while (((tmp - tmp1) < 99) && (*tmp != '\t'))
        {
          reqaddr[cnt] = *tmp;
          tmp++;
          cnt++;
        }
      reqaddr[cnt] = '\0';
      tmp++;
      cnt++;
      sscanf (tmp, "%x%c", &xi, &c);
      tmp += 9;
      cnt += 9;
      sscanf (tmp, "%c%c", pos, &c);
      tmp += 2;
      cnt += 2;
      for (i = 0; i < NUMPART; i++)
        {
          sscanf (tmp, "%x%c", &dis[i], &c);
          tmp += 9;
          cnt += 9;
        }
      sscanf (tmp, "%c", &c);
      tmp++;
      cnt++;
      if (requestor == xi)
        {
          found = 1;
          break;
        }
      tmp1 += cnt;
    }


  if (!found)
    {
      m_free (data);
      return 1;
    }

  if (remoteaddr != dis[NUMPART / 2])
    {
      m_free (data);
      return 1;
    }
  strcpy (reqsip, reqaddr);
  *pos -= '0';

  if ((end - tmp) > 0)
    memmove (tmp1, tmp, end - tmp);
  length -= cnt;

  fd = fopen (ADHOC_HOMEDIR DIRSEP_S ADDERFILE, "w");
  if (!fd)
    return 1;
  if (length)
    fwrite (data, 1, length, fd);
  fclose (fd);
  semaphore_post (semapid, SEMADD);
  m_free (data);
  return 0;
}



int
handle_cert (struct sip_msg *msg, STRLIST sender, STRLIST recipient,
             uint32_t remoteaddr)
{

  char *outname;
  FILE *out = NULL;
  char *header;
  int length;
  char *buf;
  int i, j;
  struct sockaddr_in to;
  STRLIST newsender = NULL;
  char ip[16];
  int rc;

  if (msg->outgoing)
    {
      /* This must be an incoming request, not an ougoing message */
      log_info ("Ignore CERT message from our local host\n");
      goto error;
    }

  /* why do we have to process the message, if it has no signature */
  if (msg->body_len < MIN_SIG)
    {
      log_error ("Message body is less than minimum signature length\n");
      goto error;
    }
  switch (msg->evt)
    {
    case EV_SIG:
      {

        log_info ("CERT message with Event Signature received\n");
        if (handle_header (msg, sender, recipient, EV_SIG))
          goto error;


        /* Prepare a new file name */
        get_secure_name (&outname);
        if (rc =
            systemsign_sign (outname, msg->buf + msg->hdr_len,
                             msg->buflen - msg->hdr_len))
          {
            log_error ("error happen %d\n", rc);
            goto error;
          }

        /* create from header */
        if (msg->from)
          m_free (msg->from);
        msg->from = parser_create_address (userid, 1, msg->sips);

        /* create to header */
        if (msg->to)
          m_free (msg->to);
        if (sender)
          msg->to = parser_create_address (sender->d, 0, msg->sips);

        /* create a CERT header */
        process_create_header (msg, EV_SIGREP);

        /* copy signature to buf */
        out = fopen (outname, "r");
        if (!out)
          {
            log_error ("Error reading output file\n");
            goto error;
          }
        fseek (out, 0, SEEK_END);
        length = ftell (out);
        rewind (out);

        if ((length + msg->hdr_len2) > MAX_BUF)
          m_realloc (msg->buf, length + msg->hdr_len2);
        buf = (msg->buf) + msg->hdr_len2;
        fread (buf, 1, length, out);
        msg->buflen = msg->hdr_len2 + length;
        /* close and delete temporary file */
        fclose (out);
        unlink (outname);

        /* sent it back to message initiator */
        to.sin_family = AF_INET;
        to.sin_port = bind_address->sockin.sin_port;
        to.sin_addr.s_addr = remoteaddr;
        udp_send (sendipv4, msg->buf, msg->buflen, &to);
        log_info
          ("We serve the request.\nCERT message with event Signature Reply has been sent\n");
        if (LOG_SEND)
          log_info ("Sent message %s\n", msg->buf);
        return 0;
      }

    case EV_SIGREP:
      {
        FILE *fcert = NULL;
        struct stat idliststat;
        FILE *out = NULL;

        log_info ("CERT message with Event Signature Reply received\n");
        /* we can not verify message because we are not sure
         * whether we have sender public key or not
         */
        rc = systemsign_join (msg->body, msg->body_len, remoteaddr);
        if (rc == 1)
          {
            log_error ("Error while trying to join file\n");
            goto error;
          }
        else if (rc == -1)
          {
            log_info ("Got one of the patial certificate, still need more\n");
            return 0;
          }

        /* if we have our certificate, after above procedure,
         * lets ask for partial secret key */
        log_info ("We have our Certificate from now on\n");

        fcert = fopen (ADHOC_HOMEDIR DIRSEP_S CERTFILE, "r");
        if (fcert)
          {
            /* create from header */
            if (msg->from)
              m_free (msg->from);
            msg->from = parser_create_address (userid, 1, msg->sips);

            /* create a CERT header */
            process_create_header (msg, EV_PART);

            length = get_file_length (fcert);
            msg->buflen = length + msg->hdr_len2;
            if ((msg->buflen) > MAX_BUF)
              m_realloc (msg->buf, length + msg->hdr_len2);
            buf = (msg->buf) + msg->hdr_len2;
            fread (buf, 1, length, fcert);
            fclose (fcert);


            /* broadcast our request of partial secret key */
            to.sin_family = AF_INET;
            to.sin_addr.s_addr = INADDR_BROADCAST;
            to.sin_port = bind_address->sockin.sin_port;
            udp_send (sendipv4, msg->buf, msg->buflen, &to);
            log_info
              ("Asking for Partial System key.\nCERT message with event Partial has been sent\n");
            if (LOG_SEND)
              log_info ("Sent message %s\n", msg->buf);

            /* prepare idlist file */
            semaphore_wait (semapid, SEMID);
            if (stat (ADHOC_HOMEDIR DIRSEP_S IDLISTFILE, &idliststat) != 0)
              {
                byte num = 0;
                out = fopen (ADHOC_HOMEDIR DIRSEP_S IDLISTFILE, "w");
                fwrite (&num, 1, 1, out);
                fclose (out);
              }
            semaphore_post (semapid, SEMID);
          }
        return 0;
      }
      break;

    case EV_PART:
      {
        struct stat partstat;
        FILE *fcert;

        log_info ("CERT message with Event Partial received\n");
        /* There is certificate and routing information 
         * in the body that we need to parse and import
         */
        if (handle_incoming_reg (msg) == -1)
          goto error;

        if (stat (ADHOC_HOMEDIR DIRSEP_S PARTFILE, &partstat) != 0)
          /* We dont have partial key file, so we can not serve 
           * this request
           */
          goto error;

        /* create from header */
        if (msg->from)
          m_free (msg->from);
        msg->from = parser_create_address (userid, 1, msg->sips);

        /* create to header */
        if (msg->to)
          m_free (msg->to);
        if (sender)
          msg->to = parser_create_address (sender->d, 0, msg->sips);
        else
          return 1;

        fcert = fopen (ADHOC_HOMEDIR DIRSEP_S CERTFILE, "r");
        if (fcert)
          {

            /* create a CERT header */
            process_create_header (msg, EV_PART_OK);

            length = get_file_length (fcert);
            msg->buflen = length + msg->hdr_len2;
            if ((msg->buflen) > MAX_BUF)
              m_realloc (msg->buf, length + msg->hdr_len2);
            buf = (msg->buf) + msg->hdr_len2;
            fread (buf, 1, length, fcert);
            fclose (fcert);

            /* sent our participation to message initiator */
            to.sin_family = AF_INET;
            to.sin_port = bind_address->sockin.sin_port;
            to.sin_addr.s_addr = remoteaddr;
            udp_send (sendipv4, msg->buf, msg->buflen, &to);
            log_info
              ("We agree to serve, CERT message with Partial_OK has been sent\n");
            if (LOG_SEND)
              log_info ("Sent message %s\n", msg->buf);

            return 0;
          }

        return 1;
      }
      break;

    case EV_PART_OK:
      {
        struct stat idliststat;
        uint32_t idlist[NUMPART];
        byte check;
        byte num = 0;
        FILE *fdkey;

        log_info ("CERT message with Event Partial Ok received\n");
        /* There is certificate and routing information 
         * in the body that we need to parse and import
         */
        if (handle_incoming_reg (msg) == -1)
          goto error;

        semaphore_wait (semapid, SEMID);
        out = fopen (ADHOC_HOMEDIR DIRSEP_S IDLISTFILE, "r+");
        if (!out)
          {
            /* We should have this file if we got this kind of message
             * if we dont, just ignore this message
             */
            log_error ("Get EV_PART_OK without Id list file\n");
            semaphore_post (semapid, SEMID);
            goto error;
          }
        fread (&num, 1, 1, out);


        if (num < NUMPART)
          {
            /* we still need more server, lets compare with existing ones */
            for (i = 0; i < num; i++)
              {
                fread (&(idlist[i]), 1, sizeof (idlist[i]), out);
                fread (&check, 1, 1, out);
                if (idlist[i] == remoteaddr)
                  {
                    /* we have this address already */
                    fclose (out);
                    semaphore_post (semapid, SEMID);
                    return 1;
                  }
              }

            num++;
            rewind (out);
            fwrite (&num, 1, 1, out);
            fseek (out, 0, SEEK_END);
            check = 0;
            fwrite (&remoteaddr, 1, sizeof (remoteaddr), out);
            fwrite (&check, 1, 1, out);


            if (num < NUMPART)
              {
                /* We have not had enough server */
                fclose (out);
                semaphore_post (semapid, SEMID);
                return 0;
              }

          }
        else
          {
            /* this file should be gone already */
            semaphore_post (semapid, SEMID);
            return 1;
          }

        /* We have enough neigbors who want to serve us. 
         * Create header, body and sign it
         */
        /* create from header */

        if (msg->from)
          m_free (msg->from);
        msg->from = parser_create_address (userid, 1, msg->sips);

        process_create_header (msg, EV_PART_LIST);
        sprintf (msg->buf + msg->hdr_len2, "Id_List: %x\n", remoteaddr);
        msg->buflen += 18;
        for (i = 1; i < NUMPART; i++)
          {
            fread (&(idlist[i - 1]), 1, sizeof (idlist[i - 1]), out);
            sprintf (msg->buf + msg->hdr_len2 + (i * 18), "Id_List: %x\n",
                     idlist[i - 1]);
            msg->buflen += 18;
          }
        fclose (out);
        semaphore_post (semapid, SEMID);
        /* Create temporary keyfile to be used later */
        fdkey = fopen (ADHOC_HOMEDIR DIRSEP_S KEYFILE, "w");
        fclose (fdkey);


        add_to_strlist2 (&newsender, userid, 1);
        /* sign the package */
        if (process_sign_package (msg, newsender, recipient, 0))
          {
            free_strlist (newsender);
            return 1;
          }

        free_strlist (newsender);
        idlist[NUMPART - 1] = remoteaddr;
        log_info ("\n");
        for (i = 0; i < NUMPART; i++)
          {
            to.sin_family = AF_INET;
            to.sin_addr.s_addr = idlist[i];
            to.sin_port = bind_address->sockin.sin_port;
            udp_send (sendipv4, msg->buf, msg->buflen, &to);
          }

        log_info
          ("We have enough server.\nCERT message with event Partial ID_List has been sent\n");
        if (LOG_SEND)
          log_info ("Sent message %s\n", msg->buf);
        return 0;
      }
      break;

    case EV_PART_LIST:
      {
        struct in_addr tmpaddr;
        STRLIST tmplist;
        int inthelist = 0;
        byte pos;
        FILE *fd = NULL;
        struct stat addstat;
        MPI adder[MAXSPLIT / 2];
        int cnt;
        MPI dividen;
        char *data;
        struct body_msg *body;
        char reqaddr[16] = { 0 };
        char *tmpreq;


        log_info ("CERT message with Event Partial List received\n");
        /* We should have had the certificate of the sender from previous
         * message, if we are part of the list. So we must check signature
         * and compare header and header in body
         */
        if (handle_header (msg, sender, recipient, EV_PART_LIST))
          goto error;

        body = m_alloc (sizeof (*body));
        if (parse_body
            (msg->buf + msg->hdr_len, msg->buflen - msg->hdr_len, body))
          goto error;

        sort (body->msg.idbody->id, NULL, body->msg.idbody->num);
        i = 0;
        while ((i < sock_no) && !inthelist)
          {
            for (j = 0; j < body->msg.idbody->num; j++)
              {
                if (sock_info[i].sockin.sin_addr.s_addr ==
                    body->msg.idbody->id[j])
                  {
                    inthelist = 1;
                    break;
                  }
              }
            i++;
          }

        if (!inthelist)
          {
            log_info ("Unfortunately we are not invited\n");
            return 1;
          }
        log_info ("we are in the list number %d\n", j);

        /* We are in the list number j+1 */
        pos = j;

        if (pos == (body->msg.idbody->num / 2))
          {
            FILE *fcert = NULL;
            /* We have the honor to distribute adder number 
             * Broadcast our address first to make sure everybody in the list 
             * know about it 
             */

            fcert = fopen (ADHOC_HOMEDIR DIRSEP_S CERTFILE, "r");
            if (fcert)
              {

                /* create a CERT header */
                process_create_header (msg, EV_ADDR);

                length = get_file_length (fcert);
                msg->buflen = length + msg->hdr_len2;
                if ((msg->buflen) > MAX_BUF)
                  m_realloc (msg->buf, length + msg->hdr_len2);
                buf = (msg->buf) + msg->hdr_len2;
                fread (buf, 1, length, fcert);
                fclose (fcert);

                /* Broadcast our address to the world */
                to.sin_family = AF_INET;
                to.sin_port = bind_address->sockin.sin_port;
                to.sin_addr.s_addr = INADDR_BROADCAST;
                udp_send (sendipv4, msg->buf, msg->buflen, &to);
                log_info ("We broadcast our address\n");
                if (LOG_SEND)
                  log_info ("Sent message %s\n", msg->buf);
              }

            process_generate_adder (adder,
                                    (body->msg.idbody->num - 1) / 2 + 1);

            /* Lets make a message for everybody to distribute those numbers */
            /* create from header */
            if (msg->from)
              m_free (msg->from);
            msg->from = parser_create_address (userid, 1, msg->sips);


            if (!msg->req)
              {
                tmpaddr.s_addr = remoteaddr;
                tmpreq = (char *) inet_ntoa (tmpaddr);
                strncpy (reqaddr, tmpreq, 15);
                msg->req = parser_create_req (reqaddr);
              }

            process_create_header (msg, EV_PART_ADD);
            cnt = msg->hdr_len2;
            for (i = 0; i < (body->msg.idbody->num - 1) / 2 + 1; i++)
              {
                cnt += sprintf (msg->buf + cnt, "Adder: ");
                cnt += mpi_sprint (msg->buf + cnt, adder[i], 1);
                cnt += sprintf (msg->buf + cnt, "\n");
              }

            msg->buflen = cnt;
            /* now lets sign it */
            add_to_strlist2 (&newsender, userid, 1);
            if (process_sign_package (msg, newsender, recipient, 0))
              {
                for (i = 0; i < (body->msg.idbody->num - 1) / 2 + 1; i++)
                  mpi_free (adder[i]);
                m_free (body->msg.idbody);
                m_free (body);
                free_strlist (newsender);
                return 1;
              }

            /* send adder to the rest of the server */

            for (i = 0; i < body->msg.idbody->num; i++)
              {
                if (i != pos)
                  {
                    to.sin_family = AF_INET;
                    to.sin_addr.s_addr = body->msg.idbody->id[i];
                    to.sin_port = bind_address->sockin.sin_port;
                    udp_send (sendipv4, msg->buf, msg->buflen, &to);
                  }
              }
            log_info
              ("We are the dealer.\nCERT message with event Partial adder has been sent\n");
            if (LOG_SEND)
              log_info ("Sent message %s\n", msg->buf);
            /* Here we create our own calculation */
            dividen =
              calculate_dividen1 (remoteaddr,
                                  (uint32_t *) (body->msg.idbody->id), pos,
                                  body->msg.idbody->num);

            /* calculate new certificate and return in data */
            if (handle_calc_newpart
                (&data, dividen, adder, pos, body->msg.idbody->num))
              return 1;

            /* create to header */
            if (msg->to)
              m_free (msg->to);
            msg->to = parser_create_address (sender->d, 0, msg->sips);

            /* create header type */
            process_create_header (msg, EV_PART_KEY);

            /* create body */
            strcat (msg->buf, "key: ");
            memcpy (msg->buf + msg->hdr_len2 + 5, data, strlen (data));
            strcat (msg->buf, "\n");
            msg->buflen = msg->hdr_len2 + strlen (data) + 6;

            /* sign message */

            if (process_sign_package (msg, newsender, recipient, 0))
              {
                for (i = 0; i < (body->msg.idbody->num - 1) / 2 + 1; i++)
                  mpi_free (adder[i]);
                m_free (data);
                m_free (body->msg.idbody);
                m_free (body);
                free_strlist (newsender);
                return 1;
              }

            /* send it to remote address */
            to.sin_family = AF_INET;
            to.sin_addr.s_addr = remoteaddr;
            to.sin_port = bind_address->sockin.sin_port;
            udp_send (sendipv4, msg->buf, msg->buflen, &to);
            log_info ("CERT message with event Partial Key has been sent\n");
            if (LOG_SEND)
              log_info ("Sent message %s\n", msg->buf);

            for (i = 0; i < (body->msg.idbody->num - 1) / 2 + 1; i++)
              mpi_free (adder[i]);
            m_free (data);
            m_free (body->msg.idbody);
            m_free (body);
            free_strlist (newsender);
            return 0;
          }
        else
          {
            /* we are not the distributor */
            semaphore_wait (semapid, SEMADD);
            if (stat (ADHOC_HOMEDIR DIRSEP_S ADDERFILE, &addstat) != 0)
              fd = fopen (ADHOC_HOMEDIR DIRSEP_S ADDERFILE, "w+");
            else
              fd = fopen (ADHOC_HOMEDIR DIRSEP_S ADDERFILE, "r+");
            if (!fd)
              return 1;
            /* write requester, our position and distributor's ID to a file to be used later */
            fseek (fd, 0, SEEK_END);
            fprintf (fd, "%s\t", sender->d);
            fprintf (fd, "%x\t", remoteaddr);
            fprintf (fd, "%d\t", pos);
            for (i = 0; i < body->msg.idbody->num; i++)
              {
                fprintf (fd, "%x\t", body->msg.idbody->id[i]);
              }
            fprintf (fd, "\n");
            fclose (fd);
            semaphore_post (semapid, SEMADD);
            return 0;
          }
      }
      break;

    case EV_PART_ADD:
      {
        struct body_msg *body;
        FILE *fd = NULL;
        byte pos;
        uint32_t dis[MAXSPLIT];
        uint32_t xi;
        char c;
        MPI dividen;
        char *data;
        struct in_addr tmpaddr;
        char reqaddr[16] = { 0 };
        char reqsip[100] = { 0 };

        log_info ("CERT message with Event Partial Add received\n");
        if (handle_header (msg, sender, recipient, EV_PART_ADD))
          goto error;

        /* Find requestor ip address */
        i = 5;
        if (!msg->req)
          return 1;
        while ((msg->req[i] != '\n') && i < 20)
          {
            reqaddr[i - 5] = msg->req[i];
            i++;
          }
        if (!inet_aton (reqaddr, &tmpaddr))
          {
            log_info (" can not convert address\n");
            return 1;
          }

        handle_parse_adderfile (&reqsip, &pos, (uint32_t *) dis,
                                tmpaddr.s_addr, remoteaddr);

        body = m_alloc (sizeof (*body));
        if (parse_body
            (msg->buf + msg->hdr_len, msg->buflen - msg->hdr_len, body))
          {
            for (i = 0; i < body->msg.addbody->num; i++)
              mpi_free (body->msg.addbody->adder[i]);
            m_free (body->msg.addbody);
            m_free (body);
          }

        dividen = calculate_dividen1 (xi, (uint32_t *) dis, pos, NUMPART);

        /* calculate new certificate and return in data */
        if (handle_calc_newpart
            (&data, dividen, body->msg.addbody->adder, pos, NUMPART))
          return 1;

        /* create from header */
        if (msg->from)
          m_free (msg->from);
        msg->from = parser_create_address (userid, 1, msg->sips);

        /* create to header */
        if (msg->to)
          m_free (msg->to);
        msg->to = parser_create_address (reqsip, 0, msg->sips);

        process_create_header (msg, EV_PART_KEY);
        strcat (msg->buf, "key: ");
        memcpy (msg->buf + msg->hdr_len2 + 5, data, strlen (data));
        strcat (msg->buf, "\n");
        msg->buflen = msg->hdr_len2 + strlen (data) + 6;

        add_to_strlist2 (&newsender, userid, 1);
        if (process_sign_package (msg, newsender, recipient, 0))
          {
            for (i = 0; i < (body->msg.idbody->num - 1) / 2 + 1; i++)
              mpi_free (body->msg.addbody->adder[i]);
            m_free (data);
            m_free (body->msg.addbody);
            m_free (body);
            free_strlist (newsender);
            return 1;
          }
        free_strlist (newsender);
        /* find address to requester */

        if (route_by_address (reqsip, ip))
          {
            log_error ("Can not find route to recipient\n");
            return 1;
          }
        else
          {
            /* we get the address, translate it to network number */
            if (!inet_aton (ip, &(to.sin_addr)))
              {
                log_error ("can not convert ip address\n");
                return 1;
              }
            to.sin_family = AF_INET;
            to.sin_port = bind_address->sockin.sin_port;
            udp_send (sendipv4, msg->buf, msg->buflen, &to);
            log_info ("CERT message with event Partial Key has been sent\n");
            if (LOG_SEND)
              log_info ("Sent message %s\n", msg->buf);
          }

        for (i = 0; i < body->msg.addbody->num; i++)
          mpi_free (body->msg.addbody->adder[i]);
        m_free (body->msg.addbody);
        m_free (body);

        return 0;
      }
      break;

    case EV_PART_KEY:
      {
        struct body_msg *body;
        char *data;
        FILE *fdkey = NULL;
        FILE *fdlist = NULL;
        byte match;
        byte num, numkey, check = 0;
        uint32_t id[MAXSPLIT];
        int cnt;
        struct stat keystat;
        char *key[MAXSPLIT];
        size_t keylen[MAXSPLIT];

        log_info ("CERT message with Event Partial key received\n");
        if (handle_header (msg, sender, recipient, EV_PART_KEY))
          goto error;

        semaphore_wait (semapid, SEMKEY);
        /* If we really need this message, we must have fdkey file */
        fdkey = fopen (ADHOC_HOMEDIR DIRSEP_S KEYFILE, "r+");
        if (!fdkey)
          {
            semaphore_post (semapid, SEMKEY);
            log_error ("Get EV_PART_KEY without KEYFILE\n");
            return 1;
          }

        semaphore_wait (semapid, SEMID);
        fdlist = fopen (ADHOC_HOMEDIR DIRSEP_S IDLISTFILE, "r+");
        if (!fdlist)
          {
            semaphore_post (semapid, SEMID);
            log_error ("Get EV_PART_KEY without ID LIST FILE\n");
            return 1;
          }
        cnt = 0;
        match = 0;
        fread (&num, 1, 1, fdlist);
        for (i = 0; i < num; i++)
          {
            fread (&id[i], 1, sizeof (uint32_t), fdlist);
            fread (&check, 1, 1, fdlist);
            if (check)
              cnt++;
            if (!check && id[i] == remoteaddr)
              {
                fseek (fdlist, -1, SEEK_CUR);
                check = 1;
                fwrite (&check, 1, 1, fdlist);
                match = 1;
                cnt++;
              }
          }
        fclose (fdlist);
        semaphore_post (semapid, SEMID);

        if (match || (cnt == num))
          {

            body = m_alloc (sizeof (*body));
            if (parse_body
                (msg->buf + msg->hdr_len, msg->buflen - msg->hdr_len, body))
              {
                m_free (body->msg.keybody->radmsg);
                m_free (body->msg.keybody);
                m_free (body);
              }

            length =
              handle_radix64_decode (&data, body->msg.keybody->radmsg,
                                     body->msg.keybody->length);
            m_free (body->msg.keybody->radmsg);
            m_free (body->msg.keybody);
            m_free (body);
          }
        else
          {
            semaphore_post (semapid, SEMKEY);
            return 1;
          }

        if (cnt == num)
          {
            for (i = 0; i < (num - 1); i++)
              {
                fread (&(keylen[i]), 1, sizeof (keylen[i]), fdkey);
                key[i] = m_alloc (keylen[i]);
                fread (key[i], 1, keylen[i], fdkey);
              }
            fclose (fdkey);
            key[num - 1] = data;
            keylen[num - 1] = length;

            if (handle_create_key (key, keylen, id, num))
              {
                for (i = 0; i < num; i++)
                  m_free (key[i]);
                semaphore_post (semapid, SEMKEY);
                return 1;
              }
            for (i = 0; i < num; i++)
              m_free (key[i]);
            /* we dont need any of these files anymore */
            unlink (ADHOC_HOMEDIR DIRSEP_S KEYFILE);
            unlink (ADHOC_HOMEDIR DIRSEP_S IDLISTFILE);
            semaphore_post (semapid, SEMKEY);
            log_info ("We have created our own partial key\n");
            return 0;
          }
        else if (match)
          {
            fseek (fdkey, 0, SEEK_END);
            fwrite (&length, 1, sizeof (length), fdkey);
            fwrite (data, 1, length, fdkey);
            fclose (fdkey);
            m_free (data);

            semaphore_post (semapid, SEMKEY);
            return 0;
          }
      }
      break;

    case EV_ADDR:
      {
        log_info ("CERT message with Event ADDRESS received\n");
        /* There is certificate and routing information 
         * in the body that we need to parse and import
         */
        if (handle_incoming_reg (msg) == -1)
          goto error;

        return 0;
      }
      break;
    default:
      {
      }
    }

error:
  return 1;
}
