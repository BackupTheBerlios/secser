#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <unistd.h>
#include <sys/stat.h>

#include "globals.h"
#include "adhoc.h"
#include "util.h"
#include "iobuf.h"
#include "memory.h"
#include "msg.h"
#include "udp_server.h"
#include "main.h"
#include "semaphore.h"



static void
free_msg (struct sip_msg *msg)
{
  struct sip_msg *tmp = msg;
  if (msg)
    {
      if (tmp->sign)
        m_free (tmp->sign);
      if (tmp->notsign)
        m_free (tmp->notsign);
      if (tmp->from)
        m_free (tmp->from);
      if (tmp->to)
        m_free (tmp->to);
      m_free (msg);
    }
  msg = NULL;
}

struct sip_msg *
create_message ()
{

  struct sip_msg *msg;

  msg = m_alloc (sizeof (struct sip_msg));
  msg->orig = NULL;
  msg->buf = NULL;
  msg->body = NULL;
  msg->sign = NULL;
  msg->notsign = NULL;
  msg->from = NULL;
  msg->to = NULL;
  msg->via1 = NULL;
  msg->via2 = NULL;
  msg->sips = 0;

  return msg;
}

/* Handle a client connection on the file descriptor CONNECTION_FD. */

int
receive_connection (char *buffer, unsigned bytes_read,
                    struct sockaddr_in *from)
{

  char orig[MAX_BUF + 1] = { 0 };
  char *tmp;


  struct sip_msg *msg;
  STRLIST sender = NULL;
  STRLIST recipient = NULL;
  STRLIST tmplist;
  struct sockaddr_in to;
  int rc;
  time_t logtime;
  int i;



/* SIP Message can be request or reply message. 
Request messge consists of :
1. Method
2. intended recipient
3. SIP version

reply consists of :
1. SIP version 
2. reply number
3. reason

In our case, there are only 3 types of message :
1. SIP REGISTER message (broadcast them).
2. Other SIP message (sign and encrypt).
3. CERTIFICATE exchange messages (do processing) 

We need to make the decision here */

/* Preparing SIP message */

  msg = create_message ();
  memcpy (orig, buffer, bytes_read);
  msg->orig = orig;
  msg->buf = buffer;
  msg->len = bytes_read;
  msg->buflen = bytes_read;
  /*
     msg->outgoing = 0;
     if (from->sin_addr.s_addr == 0x100007f) 
     msg->outgoing = 1;
     else {
     for (i=0; i < sock_no; i++) { */
  /* Message outgoing must be from 127.0.0.1
   * to remove problem when we are broadcasting
   */
/*
		if ((sock_info[i].sockin.sin_addr.s_addr == from->sin_addr.s_addr)) {
		    log_info ("Ignoring message from localhost address other then 127.0.0.1\n");
		    goto error;
		}		
	    }
	}	
*/
  msg->outgoing = 0;
  for (i = 0; i < sock_no; i++)
    {
      if ((sock_info[i].sockin.sin_addr.s_addr == from->sin_addr.s_addr))
        {
          msg->outgoing = 1;
          break;
        }
    }
  /* parse message, get type, sender and recipient if possible */
  if (parse_msg (msg, &sender, &recipient))
    {
      /* something is wrong, free the message */
      free_msg (msg);
      log_error ("There is something wrong when parsing the message\n");
      return 1;
    }

  if (LOG_MSG)
    {
      log_info ("***** BEGIN INCOMING MESSAGE DUMP *****\n");
      log_info ("Message type :%u\n", msg->type);
      if (msg->outgoing)
        log_info ("This is an outgoing message\n");
      else
        log_info ("This is an incoming message\n");
      log_info ("Message length : %u\n", msg->buflen);
      if (LOG_MSG > 1)
        {
          for (tmplist = sender; tmplist; tmplist = tmplist->next)
            log_info ("Address of sender: %s\n", tmplist->d);
          for (tmplist = recipient; tmplist; tmplist = tmplist->next)
            log_info ("Address of receiver: %s\n", tmplist->d);
          log_info ("%s\n", strndup (msg->buf, msg->buflen));
        }
    }

  /* Create a response, depend on type of message */
  switch (msg->type)
    {
    case MSG_REG:
      /* Register message */
      {
        /* Is there any better way to differentiate msg->outgoing 
         * from our own broadcast?
         */
        if (msg->outgoing && (msg->body_len < MIN_SIG))
          {
            IOBUF tmpcert;
            struct stat tmpstat;

            /* create response to this message */
            if (process_reg_response (msg, sender, recipient))
              {
                printf ("Can not create message response\n");
                goto error;
              }

            /* prepare file for temporary cert file */
            if (stat (ADHOC_HOMEDIR DIRSEP_S TMPCERTFILE, &tmpstat) != 0)
              {
                tmpcert = iobuf_create (ADHOC_HOMEDIR DIRSEP_S TMPCERTFILE);
                iobuf_close (tmpcert);
              }


            /* we either have our certificate in the body signed by the 
             * system (SIP REGISTER MESSAGE) or we have our certificate 
             * signed by our own key (CERT SIGN MESSAGE) we just need to
             * broadcast it for now
             */
            to.sin_family = AF_INET;
            to.sin_addr.s_addr = INADDR_BROADCAST;
            to.sin_port = bind_address->sockin.sin_port;
            udp_send (sendipv4, msg->buf, msg->buflen, &to);
            logtime = time (NULL);
            log_info ("%s finish with outgoing register\n", ctime (&logtime));
            if (LOG_MSG > 1)
              {
                log_info ("*****BEGIN RESPONSE MESSAGE *****\n");
                log_info ("Message Length : %d\n", msg->buflen);
                log_info ("%s\n", strndup (msg->buf, msg->buflen));
              }
          }
        else if (!msg->outgoing)
          {
            /* Incoming message */

            /* why do we have to process the message, if it has no signature */
            if (msg->body_len < MIN_SIG)
              {
                log_error
                  ("Message body is less than minimum signature length\n");
                goto error;
              }

            rc = handle_incoming_reg (msg);
            if (rc == -1)
              goto error;
            else if ((rc == 1) || (rc == 2))
              {
                /* We have new routing information, 
                 * broadcast it to our neighbors
                 */
                to.sin_family = AF_INET;
                to.sin_addr.s_addr = INADDR_BROADCAST;
                to.sin_port = bind_address->sockin.sin_port;
                udp_send (sendipv4, msg->orig, msg->len, &to);
                log_info ("broadcasting new route\n");
              }
            /* everything is ok until now, we just have to forward
             * header in msg->orig to local sip server.
             * Do we have to forward it, or just for security server?
             */
            to.sin_family = AF_INET;
            to.sin_addr.s_addr = 0x100007f;;
            to.sin_port = (uint16_t) htons (SIP_PORT);
            udp_send (sendipv4, msg->orig, msg->hdr_len, &to);
            log_info ("Message has been forwarded to local sip server\n");
            logtime = time (NULL);
            log_info ("%s finish with incoming register message\n",
                      ctime (&logtime));
          }
        else
          log_info
            ("ignoring register message, we broadcasted this message\n");
      }
      break;

    case MSG_OTH:
      /* Let ser decide what to do with other type of message,
       *  such as, SUBSCRIBE, NOTIFY, MESSAGE, etc
       */

    case MSG_REP:
      /* Reply message */
      {

        if (msg->outgoing)
          {

            char ip[16] = { 0 };
            //size_t port;

            /* we need to remove via message that we inserted
             * when the request came
             */
            if (msg->type == 1)
              {
                if (process_remove_via (msg))
                  {
                    log_error ("Cannot remove our via header\n");
                    /* just go on and forward the message */
                  }
                /* note that for reply message, the sender is in
                 * To header not in from header, we need to interchange them
                 */
                tmplist = sender;
                sender = recipient;
                recipient = tmplist;
              }

            /* find address to recipient */
            if (recipient)
              {
                if (route_by_address (recipient->d, ip))
                  {
                    if (msg->type == 1)
                      {
                        /* This is a reply message, at least
                         * we had checked this message when it came.
                         * So, it will not hurt if we learn the route
                         * from VIA header
                         */
                        if (!parse_via_header (msg, ip) &&
                            inet_aton (ip, &(to.sin_addr)))
                          {
                            add_route_from_via (recipient->d, ip);
                          }
                        else
                          {
                            log_error
                              ("Can not convert or find addr from via\n");
                            goto error;

                          }
                      }
                    else
                      {
                        log_error ("Can not find route to recipient\n");
                        goto error;
                      }
                  }
              }
            else
              goto error;

            /* We need to sign all outgoing reply message */
            if (process_sign_package (msg, sender, recipient, 1))
              {
                log_error ("Can not sign the package\n");
                goto error;
              }
            /* we get the address, translate it to network number */
            if (!inet_aton (ip, &(to.sin_addr)))
              {
                log_error ("can not convert ip address\n");
                goto error;
              }
            to.sin_family = AF_INET;
            to.sin_port = bind_address->sockin.sin_port;
            udp_send (sendipv4, msg->buf, msg->buflen, &to);

            logtime = time (NULL);
            log_info
              ("%s finish with outgoing reply or other request message\n",
               ctime (&logtime));
            if (LOG_MSG > 1)
              {
                log_info ("*****BEGIN RESPONSE MESSAGE*****\n");
                log_info ("Message Length : %d\n", msg->buflen);
                log_info ("%s", strndup (msg->buf, msg->buflen));
              }
          }
        else
          {
            /* Incoming message */

            /* why do we have to process the message, if it has no signature */
            if (msg->body_len < MIN_SIG)
              {
                log_error
                  ("Message body is less than minimum signature length\n");
                goto error;
              }
            /* verify incoming reply message */
            if (process_verify_package (msg))
              {
                log_error ("Error verifying message\n");
                goto error;
              }

            /* this is an incoming request, so we need to insert VIA header 
             * to make reply goes to this server again i.e. forwarded to here
             * by ser
             */
            if (msg->type == 3)
              {
                if (process_insert_via (msg))
                  {
                    log_error ("Cannot insert via header\n");
                    /* just go on and forward the message */
                  }
              }
            /* Do we have to compare between the header in header and signed header? 
             * or just simply forward body (header + body) to local sip server?
             */

            /* We use local address to send message to local SIP proxy server */
            to.sin_family = AF_INET;
            to.sin_addr.s_addr = 0x100007f;
            to.sin_port = htons (SIP_PORT);
            udp_send (sendipv4, msg->buf, msg->buflen, &to);

            logtime = time (NULL);
            log_info ("%s finish with incoming reply or other message\n",
                      ctime (&logtime));
            if (LOG_MSG > 1)
              {
                log_info ("*****ORIGINAL MESSAGE*****\n");
                log_info ("%s", strndup (msg->buf, msg->buflen));
              }
          }

      }
      break;

    case MSG_CERT:
      /* CERT message */
      {
        if (handle_cert (msg, sender, recipient, from->sin_addr.s_addr))
          goto error;

        /* everything is ok here */
        logtime = time (NULL);
        log_info ("%s finish with incoming CERT message\n", ctime (&logtime));
      }
      break;


    }
  free_strlist (recipient);
  free_strlist (sender);
  free_msg (msg);
  return 0;



error:

  if (recipient)
    free_strlist (recipient);
  if (sender)
    free_strlist (sender);
  free_msg (msg);
  return 1;
}
