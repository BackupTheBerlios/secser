#include <stdio.h>
#include <stdlib.h>

#include "globals.h"
#include "parser.h"
#include "msg.h"
#include "adhoc.h"
#include "memory.h"
#include "util.h"

char *
parser_create_address (char *address, int from, int sips)
{
  char *header = NULL;

  if (address)
    {
      if (from)
        {
          if (sips)
            {
              header = (char *) m_alloc (8 + 5 + strlen (address) + 1);
              strcpy (header, "From: <sips:");
            }
          else
            {
              header = (char *) m_alloc (8 + 4 + strlen (address) + 1);
              strcpy (header, "From: <sip:");
            }
          strcat (header, address);
          strcat (header, ">");
        }
      else
        {
          if (sips)
            {
              header = (char *) m_alloc (6 + 5 + strlen (address) + 1);
              strcpy (header, "To: <sips:");
            }
          else
            {
              header = (char *) m_alloc (6 + 4 + strlen (address) + 1);
              strcpy (header, "To: <sip:");
            }
          strcat (header, address);
          strcat (header, ">");
        }
    }
  return header;
}

char *
parser_create_req (char *buff)
{
  char address[16] = { 0 };
  char *ret = NULL;

  struct in_addr tmpaddr;

  strncpy (address, buff, 15);
  if (inet_aton (address, &tmpaddr))
    {
      ret = m_alloc_clear (5 + strlen (address) + 2);
      strcat (ret, "Req: ");
      strcat (ret, address);
      strcat (ret, "\n");
    }
  return ret;
}

int
check (char *text, size_t len, char *buf, char *end)
{
  char *tmp = buf;
  int i;
  for (i = 0; i < len; i++)
    {
      if (tolower (*text) != tolower (*tmp))
        return 0;
      text++;
      tmp++;
    }

  /* check for ':' if end is not null */
  if (end)
    {
      /* it is possible to have a lot of white char after text */
      for (tmp; (*tmp == ' ') && ((tmp) < end); tmp++);
      if (*tmp == ':')
        return (tmp - buf + 1);
      else
        return 0;
    }
  else
    return (tmp - buf);
}

/* end of header can be CRLF or might be LF,
 * either way, next line must not ' ', otherwise
 * it is still in one header field
 */
size_t
find_end (const char *buf, const char *end)
{
  char *tmp;
  char out = 0;

  tmp = (char *) buf;
  while (tmp < end && !out)
    {
      if (*tmp == '\r' && *(tmp + 1) == '\n')
        {                       // CRLF
          if (*(tmp + 2) != ' ')        // still in one header field
            out = 1;
          tmp += 2;
        }
      else if (*tmp == '\n' && *(tmp + 1) != ' ')
        {
          out = 1;
          tmp++;
        }
      else if (*tmp == '\n')    // Just LF, not standard for end of header 
        {                       // but could happen; try to accept that
          out = 1;
          tmp++;
        }
      else
        tmp++;
    }
  return (tmp - buf);
}

int
get_address (const char *buffer, char *address, int length, int *type)
{
  char *first;
  char *begin;
  char *end;
  char *tmp = (char *) buffer;
  int finish = 0;
  int error = 0;
  int status = ADDR_START;
  int off = 0;
  int n;


  /* remove white space if any */
  for (; (*tmp == ' ') && ((tmp - buffer) < length); tmp++);

  first = begin = tmp;
  end = (char *) (buffer + length);
  if ((end - first) < 5)
    return 1;
  while (!error && !finish && ((tmp - buffer) < length))
    {
      switch (*tmp)
        {
        case '"':
          {
            if (status == ADDR_START)
              {
                status = QUOTE_START;
                end = tmp - 1;
                tmp++;
              }
            else if (status == QUOTE_START)
              {
                status = QUOTE_END;
                tmp++;
                /* remove whithe space if any */
                for (; (*tmp == ' ') && ((tmp - buffer) < length); tmp++);
                begin = tmp;
              }
            else
              error = 1;
          }
          break;

        case '<':
          {
            if (status == ADDR_START || status == QUOTE_END)
              {
                status = ADDR_BEGIN;
                tmp++;
                begin = tmp;
              }
            else if (status == ADDR_BEGIN)
              error = 1;
            else
              tmp++;
          }
          break;

        case '>':
          {
            if (status == ADDR_BEGIN)
              {
                status = ADDR_END;
                finish = 1;
                end = tmp;
              }
            if (status == ADDR_START || status == QUOTE_END)
              error = 1;
          }
          break;

        default:
          tmp++;
        }
    }

  /* if any error happen */
  if (error)
    return 1;
  n = 0;
  if (finish)
    {
      /* This is a normal case */

      if (off = check ("SIPS", 4, begin, end))
        {
          n = end - (begin + off);
          *type = 1;
        }
      else if (off = check ("SIP", 3, begin, end))
        {
          n = end - (begin + off);
          *type = 0;
        }
      else
        return 1;

      if ((n < 79) && (n > 0))
        {
          strncpy (address, begin + off, n);
          *(address + n) = '\0';
        }
      return 0;
    }

  else if (!finish && (status == ADDR_START || status == QUOTE_END))
    {
      /* Header just contain usual address, no comma, semicolon or question mark */
      if (begin >= (buffer + length - 1))
        {
          /* we have the address at the beginning */
          if (off = check ("SIPS", 4, first, end))
            {
              n = end - (first + off);
              *type = 1;
            }
          else if (off = check ("SIP", 3, first, end))
            {
              n = end - (first + off);
              *type = 0;
            }
          else
            return 1;

          if ((n < 79) && (n > 0))
            {
              strncpy (address, first + off, n);
              *(address + n) = '\0';
            }
        }

      else
        {
          /* we have it at the end */
          if (off = check ("SIPS", 4, begin, end))
            {
              n = buffer + length - (begin + off);      /* SIPS: */
              *type = 1;
            }
          else if (off = check ("SIP", 3, begin, end))
            {
              n = buffer + length - (begin + off);      /* SIP: */
              *type = 0;
            }
          else
            return 1;

          if ((n < 79) && (n > 0))
            {
              strncpy (address, begin + off, n);
              *(address + n) = '\0';
            }

        }
      return 0;
    }
  else
    return 1;
}

int
parse_first_line (char **buf, const char *end, int *type)
{
  int offset;
  char *fline;

  offset = find_end (*buf, end);
  if (offset < 4)
    /* first line to short, just go out */
    return 1;
  fline = (char *) strndup (*buf, offset);
  if (LOG_PARSER)
    log_info ("First line is : %s\n", fline);
  if (check ("REGISTER", 8, fline, NULL))
    {
      //log_info ("REGISTER\n");
      *type = MSG_REG;
    }
  else if (check ("SIP/2.0", 7, fline, NULL))
    {
      //log_info ("SIP/2.0\n");
      *type = MSG_REP;
    }
  else if (check ("CERT", 4, fline, NULL))
    {
      //log_info ("CERT\n");
      *type = MSG_CERT;
    }
  else
    *type = MSG_OTH;
  *buf += offset;
  m_free (fline);
  return 0;
}

int
parse_event (char *buffer, char *end)
{
  char *tmp = buffer;

  for (; (*tmp == ' ') && (tmp < end); tmp++);
  if ((end - tmp) < 8)
    return 0;

  if (check (EV_SIG_STR, EV_SIG_LEN - 2, tmp, NULL))
    {
      if (*(tmp + EV_SIG_LEN - 2) == '\r')
        return EV_SIG;
      else if ((tmp[EV_SIG_LEN - 2] == '_') &&
               (tolower (tmp[EV_SIG_LEN - 1]) == 'r'))
        return EV_SIGREP;
    }
  else if (check (EV_PART_STR, EV_PART_LEN - 2, tmp, NULL))
    {
      if (tmp[EV_PART_LEN - 2] == '\r')
        return EV_PART;
      else if (tmp[EV_PART_LEN - 2] == '_')
        {
          if (tolower (tmp[EV_PART_LEN - 1]) == 'o')
            return EV_PART_OK;
          else if (tolower (tmp[EV_PART_LEN - 1]) == 'i')
            return EV_PART_LIST;
          else if (tolower (tmp[EV_PART_LEN - 1]) == 'a')
            return EV_PART_ADD;
          else if (tolower (tmp[EV_PART_LEN - 1]) == 'k')
            return EV_PART_KEY;
        }
    }
  else if (check (EV_ADDR_STR, EV_ADDR_LEN - 2, tmp, NULL))
    {
      return EV_ADDR;
    }
  log_error ("hmm.. Dunno what kind of event is this\n");
  return 0;
}

/* we try to remove error because LF and CRLF things
 * at the end of the header
 */
int
not_out (char **buffer)
{
  char *tmp = *buffer;
  if (*tmp == '\r' && *(tmp + 1) == '\n')
    {
      /* we find CRLF, then go out */
      tmp += 2;
      *buffer = tmp;
      return 0;
    }
  else if (*tmp == '\n')
    {
      /* again this is not standard but this happen
       * lets try to accept it
       */
      tmp++;
      *buffer = tmp;
      return 0;
    }
  else
    return 1;
}

int
parse_msg (struct sip_msg *msg, STRLIST * sender, STRLIST * recipient)
{

  char *tmp;
  char *end;
  int length;
  int offset;
  char *header;
  char address[80] = { 0 };
  char *body;
  int body_length;
  int off;
  int type;
  int evt;



  /* parse the data */
  tmp = msg->buf;
  end = msg->buf + msg->len;

  /* strip the beginning space */
  for (tmp; ((*tmp == '\n') || (*tmp == '\r'))
       && ((tmp - msg->buf) < length); tmp++);

  if (parse_first_line (&tmp, end, &(msg->type)))
    return 1;

  offset = tmp - msg->buf;
  do
    {
      switch (*tmp)
        {
        case 't':
        case 'T':
          {
            if (off = check ("TO", 2, tmp, end))
              {
                if (LOG_PARSER)
                  log_info ("Header To found in %u\n", tmp - msg->buf);
                offset += off;
                offset += find_end (tmp + off, end);

                /* find the user address */
                tmp += off;
                if (get_address
                    (tmp, address, msg->buf + offset - tmp, &(msg->sips)))
                  {

                    tmp = msg->buf + offset;
                    break;
                  }

                add_to_strlist2 (recipient, address, 0);
                if (LOG_PARSER)
                  log_info ("The address is : %s\n", address);

                /* We only need one to header */
                if (!msg->to)
                  msg->to = parser_create_address (address, 0, msg->sips);
                tmp = msg->buf + offset;

                break;
              }
          }


        case 'f':
        case 'F':
          {
            if (off = check ("FROM", 4, tmp, end))
              {
                if (LOG_PARSER)
                  log_info ("Header From found in %u\n", tmp - msg->buf);

                offset += off;
                /* find the end of this header */
                offset += find_end (tmp + off, end);

                /* find the user address */
                tmp += off;

                if (get_address
                    (tmp, address, msg->buf + offset - tmp, &(msg->sips)))
                  {
                    tmp = msg->buf + offset;
                    break;
                  }

                add_to_strlist2 (sender, address, 0);
                if (LOG_PARSER)
                  log_info ("The address is : %s\n", address);

                /* We only require one from */
                if (!msg->from)
                  {
                    /* copy from header to be used later */
                    msg->from = parser_create_address (address, 1, msg->sips);
                  }
                tmp = msg->buf + offset;


                break;
              }
          }

        case 'v':
        case 'V':
          {
            if (off = check ("VIA", 3, tmp, end))
              {
                if (LOG_PARSER)
                  log_info ("Header Via found in %u\n", tmp - msg->buf);

                offset += off;
                /* find the end of this header */
                offset += find_end (tmp + off, end);
                if (!msg->via1)
                  msg->via1 = tmp;
                else if (!msg->via2)
                  msg->via2 = tmp;
                tmp = msg->buf + offset;
                break;
              }
          }

        case 'e':
        case 'E':
          {
            if (off = check ("Event", 5, tmp, end))
              {
                if (LOG_PARSER)
                  log_info ("Header Event found in %u\n", tmp - msg->buf);

                offset += off;
                /* find the end of this header */
                offset += find_end (tmp + off, end);
                tmp += off;
                msg->evt = parse_event (tmp, msg->buf + offset);
                tmp = msg->buf + offset;
                break;
              }
          }

        case 'r':
        case 'R':
          {
            if (off = check ("REQ", 3, tmp, end))
              {

                if (LOG_PARSER)
                  log_info ("Header Requester found in %u\n", tmp - msg->buf);

                offset += off;
                /* find the end of this header */
                offset += find_end (tmp + off, end);

                /* find the user address */
                tmp += off;
                for (tmp; (*tmp == ' ') && ((tmp) < end); tmp++);
                if (!msg->req)
                  msg->req = parser_create_req (tmp);
                tmp = msg->buf + offset;
                break;
              }
          }

        default:
          {
            if (LOG_PARSER)
              log_info ("Other header found in %u\n", tmp - msg->buf);

            offset += find_end (tmp, end);
            tmp = msg->buf + offset;

          }
        }
    }
  while (not_out (&tmp) && tmp < end);

  msg->hdr_len = msg->hdr_len2 = tmp - msg->buf;
  /* We still have data left, it means body */
  if (tmp < end)
    {
      msg->body_len = end - tmp;
      msg->body = tmp;
    }

  return 0;
}

/* Find out if there is a public key to be imported
 * in the message. Return the length of the package
 * if public key found or 0 otherwise */
int
check_public_key (const char *begin, const char *end)
{
  char *tmp = (char *) begin;
  static char *pgp_begin = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
  static unsigned int begin_len = 36;
  static char *pgp_end = "-----END PGP PUBLIC KEY BLOCK-----";
  static unsigned int end_len = 34;

  unsigned int i;

  for (i = 0; i < begin_len; i++, tmp++)
    if (*tmp != pgp_begin[i])
      return 0;

  while ((*tmp != '-' || tmp[1] != '-') && tmp < end)
    tmp++;

  if (tmp < end)
    {

      for (i = 0; i < end_len; i++, tmp++)
        {
          if (*tmp != pgp_end[i])
            return 0;
        }
    }
  return (tmp - begin);
}

struct reg_body *
create_reg_body ()
{
  struct reg_body *tmp_body;

  /* prepare register body */
  tmp_body = (struct reg_body *) m_alloc (sizeof (struct reg_body));
  if (!tmp_body)
    {
      log_error ("Can not allocate memory for register body messge\n");
      return NULL;
    }
  memset (tmp_body, 0, sizeof (struct reg_body));

  return tmp_body;
}

struct id_body *
create_id_body ()
{
  struct id_body *tmp_body;

  /* prepare register body */
  tmp_body = (struct id_body *) m_alloc (sizeof (struct id_body));
  if (!tmp_body)
    {
      log_error ("Can not allocate memory for id list body message\n");
      return NULL;
    }
  memset (tmp_body, 0, sizeof (struct id_body));

  return tmp_body;
}

struct add_body *
create_add_body ()
{
  struct add_body *tmp_body;

  /* prepare register body */
  tmp_body = (struct add_body *) m_alloc (sizeof (struct add_body));
  if (!tmp_body)
    {
      log_error ("Can not allocate memory for adder body message\n");
      return NULL;
    }
  memset (tmp_body, 0, sizeof (struct add_body));

  return tmp_body;
}

struct key_body *
create_key_body ()
{
  struct key_body *tmp_body;

  /* prepare register body */
  tmp_body = (struct key_body *) m_alloc (sizeof (struct key_body));
  if (!tmp_body)
    {
      log_error ("Can not allocate memory for adder body message\n");
      return NULL;
    }
  memset (tmp_body, 0, sizeof (struct key_body));

  return tmp_body;
}

/* Parse body and find user address, ip address, port
 * and public key. The body it self might be encrypted.
 * we have to add functionality to decrypt it first in
 * here or in the calling function */

int
parse_body (char *buffer, int length, struct body_msg *body)
{
  char *tmp = buffer;
  char *end = buffer + length;
  int offset;
  int off;
  char *bodyline;
  char *address;
  uint16_t port = 0;
  size_t keylen;
  struct reg_body *tmp_body = NULL;
  struct id_body *tmp_body1 = NULL;
  struct add_body *tmp_body2 = NULL;
  struct key_body *tmp_body3 = NULL;




/* strip the beginning space */
  for (tmp; ((*tmp == '\n') || (*tmp == '\r'))
       && ((tmp - buffer) < length); tmp++);
  offset = tmp - buffer;
  do
    {
      switch (*tmp)
        {
        case 'U':
        case 'u':
          {
            if (!tmp_body)
              tmp_body = create_reg_body ();
            body->type = BODYREG;
            if (off = check ("USER", 4, tmp, end))
              {
                if (LOG_PARSER)
                  log_info ("Body USER found in %u\n", tmp - buffer);
                offset += off;

                /* find the end of this header */
                offset += find_end (tmp + off, end);

                /* find the user address */
                tmp = tmp + off;
                for (tmp; (*tmp == ' ') && ((tmp) < end); tmp++);

                /* copy it to structure */
                tmp_body->user =
                  (char *) strndup (tmp, buffer + offset - tmp - 1);
                tmp_body->user_len = buffer + offset - tmp - 1;

                if (LOG_PARSER)
                  log_info ("The user is : %s\n", tmp_body->user);
                tmp = buffer + offset;
                break;
              }
          }

        case 'A':
        case 'a':
          {
            if (off = check ("ADDRESS", 7, tmp, end))
              {
                if (!tmp_body)
                  tmp_body = create_reg_body ();
                body->type = BODYREG;
                if (LOG_PARSER)
                  log_info ("Body ADDRESS found in %u\n", tmp - buffer);
                offset += off;

                /* find the end of this header */
                offset += find_end (tmp + off, end);

                /* find the IP address */
                tmp = tmp + off;
                for (tmp; (*tmp == ' ') && ((tmp) < end); tmp++);


                /* copy it to structure */
                tmp_body->ip =
                  (char *) strndup (tmp, buffer + offset - tmp - 1);
                tmp_body->ip_len = buffer + offset - tmp - 1;

                if (LOG_PARSER)
                  log_info ("The IP address is : %s\n", tmp_body->ip);
                tmp = buffer + offset;
                break;
              }
            else if (off = check ("ADDER", 5, tmp, end))
              {
                char *data;
                MPI val = mpi_alloc (0);

                if (!tmp_body2)
                  tmp_body2 = create_add_body ();
                body->type = BODYADD;

                if (LOG_PARSER)
                  log_info ("Body Adder found in %u\n", tmp - buffer);

                offset += off;
                /* find the end of this line */
                offset += find_end (tmp + off, end);

                /* find the adder */
                tmp = tmp + off;
                for (tmp; (*tmp == ' ') && ((tmp) < end); tmp++);
                data = m_alloc_clear (buffer + offset - tmp);
                strncpy (data, tmp, buffer + offset - tmp - 1);

                if (mpi_fromstr (val, data))
                  {
                    mpi_free (val);
                    m_free (data);
                    tmp = buffer + offset;
                    break;
                  }
                tmp_body2->adder[tmp_body2->num] = val;
                (tmp_body2->num)++;
                m_free (data);
                tmp = buffer + offset;
                break;
              }
          }

        case 'P':
        case 'p':
          {
            if (off = check ("PORT", 4, tmp, end))
              {
                if (!tmp_body)
                  tmp_body = create_reg_body ();
                body->type = BODYREG;
                if (LOG_PARSER)
                  log_info ("Body PORT found in %u\n", tmp - buffer);
                offset += off;

                /* find the end of this header */
                offset += find_end (tmp + off, end);

                /* find the user address */
                tmp = tmp + off;
                for (tmp; (*tmp == ' ') && ((tmp) < end); tmp++);
                for (tmp; tmp < (buffer + offset - 1); tmp++)
                  {
                    if ((*tmp - 48) <= 9 && (*tmp - 48) >= 0)
                      port = port * 10 + (*tmp - 48);
                    else
                      {
                        log_error ("Error while changing port to number\n");
                        return 1;
                      }
                  }

                /* copy it to structure */
                tmp_body->port = port;

                if (LOG_PARSER)
                  log_info ("The PORT is : %u\n", port);
                tmp = buffer + offset;
                break;
              }
          }

        case '-':
          {
            if (!tmp_body)
              tmp_body = create_reg_body ();
            body->type = BODYREG;
            if (keylen = check_public_key (tmp, end))
              {
                tmp_body->public_key = (char *) strndup (tmp, keylen);
                tmp_body->pk_len = keylen;

                if (LOG_PARSER)
                  log_info ("We found begin pgp length : %u\n"
                            "%s\n", keylen, strndup (tmp, keylen));
                tmp += (keylen + 1);
              }
          }
          break;

        case 'I':
        case 'i':
          {
            uint32_t address;
            char c;
            if (!tmp_body1)
              tmp_body1 = create_id_body ();
            body->type = BODYID;
            if (off = check ("ID_LIST", 7, tmp, end))
              {
                if (LOG_PARSER)
                  log_info ("Body id list found in %u\n", tmp - buffer);
                offset += off;
                /* find the end of this header */
                offset += find_end (tmp + off, end);

                /* find the id */
                tmp = tmp + off;
                for (tmp; (*tmp == ' ') && ((tmp) < end); tmp++);
                if (sscanf (tmp, "%x%c", &address, &c) == 2)
                  {
                    tmp_body1->id[tmp_body1->num] = address;
                    (tmp_body1->num)++;
                  }
                tmp = buffer + offset;
                break;
              }
          }

        case 'K':
        case 'k':
          {
            int length;
            if (!tmp_body3)
              tmp_body3 = create_key_body ();
            body->type = BODYKEY;
            if (off = check ("KEY", 3, tmp, end))
              {
                if (LOG_PARSER)
                  log_info ("Body key found in %u\n", tmp - buffer);
                offset += off;
                /* find the end of this header */
                offset += find_end (tmp + off, end);

                /* find the key */
                tmp = tmp + off;
                for (tmp; (*tmp == ' ') && ((tmp) < end); tmp++);
                length = buffer + offset - tmp;
                tmp_body3->radmsg = m_alloc (length);
                strncpy (tmp_body3->radmsg, tmp, length - 1);
                tmp_body3->radmsg[length] = '\0';
                tmp_body3->length = length - 1;
                tmp = buffer + offset;
                break;
              }
          }
        default:
          {

            log_error
              ("Other body type is found %c. Dont know what to do in %u\n",
               *tmp, tmp - buffer);
            return 1;
          }
        }
    }
  while (*tmp != '\n' && *tmp != '\r' && tmp < end);

  if (body->type == BODYREG)
    {
      /* check if any field is empty, we need a full one */
      if (!tmp_body->user || !tmp_body->ip || (tmp_body->port == 0)
          || !tmp_body->public_key)
        {

          if (tmp_body->user)
            m_free (tmp_body->user);
          if (tmp_body->ip)
            m_free (tmp_body->ip);
          if (tmp_body->public_key)
            m_free (tmp_body->public_key);
          m_free (tmp_body);
          return 1;
        }
      else
        {

          body->msg.regbody = tmp_body;
          tmp_body = NULL;
          return 0;
        }
    }
  else if (body->type == BODYID)
    {
      body->msg.idbody = tmp_body1;
      tmp_body1 = NULL;
      return 0;
    }
  else if (body->type == BODYADD)
    {
      body->msg.addbody = tmp_body2;
      tmp_body2 = NULL;
      return 0;
    }
  else if (body->type == BODYKEY)
    {
      body->msg.keybody = tmp_body3;
      tmp_body2 = NULL;
      return 0;
    }
  return 1;
}

int
parse_via_header (struct sip_msg *msg, char ip[])
{
  size_t len;
  char *via = NULL;
  char *addr = NULL;
  char *tmp = NULL;
  char *tmp1 = NULL;
  int i;

  if (!msg->via1)
    return 1;

  /* locate via and its length first */
  via = msg->orig + (msg->via1 - msg->buf);
  len = find_end (via, msg->orig + msg->len);

  addr = m_alloc (len + 1);
  memcpy (addr, via, len);
  addr[len] = '\0';

  tmp = strstr (addr, "SIP/2.0");
  if (tmp)
    {
      len -= (tmp - addr);
      if ((tmp1 = strstr (tmp, "UDP")) || (tmp1 = strstr (tmp, "TCP")))
        {
          tmp1 += 3;
          len -= 3;
        }
      else
        {
          m_free (addr);
          return 1;             // No UDP or TCP
        }
      while ((*tmp1 == ' ') && (len > 0))
        {
          tmp1++;               // remove space
          len--;
        }

      tmp = tmp1;
      while ((isdigit (*tmp1) || (*tmp1 == '.')) && (len > 0)
             && (tmp1 - tmp < 15))
        {
          /* Just copy the bytes now,
           * we will check if it is right or not with inet_aton later on 
           */
          ip[tmp1 - tmp] = *tmp1;
          tmp1++;
          len--;
        }
      ip[tmp1 - tmp + 1] = '\0';
      m_free (addr);
      return 0;
    }
  else
    return 1;                   // no SIP/2.0    
}
