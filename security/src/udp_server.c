#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <arpa/inet.h>
#ifdef __linux__
#include <linux/types.h>
#include <linux/errqueue.h>
#endif

#include "util.h"
#include "ip_addr.h"
#include "udp_server.h"
#include "adhoc.h"

struct socket_info *bind_address;
struct socket_info *sendipv4 = NULL;

int
udp_init (struct socket_info *sock_info)
{
  struct sockaddr_in *addr;
  int optval;

  addr = (&sock_info->sockin);
  memset (addr, 0, sizeof (struct sockaddr_in));
  addr->sin_family = AF_INET;
  memcpy (&(addr->sin_addr.s_addr), &(sock_info->address.s_addr),
          sizeof ((sock_info->address.s_addr)));
  addr->sin_port = htons (sock_info->port_no);

  sock_info->socket = socket (AF_INET, SOCK_DGRAM, 0);
  if (sock_info->socket == -1)
    {
      printf ("ERROR: udp_init: socket: %s\n", strerror (errno));
      goto error;
    }
  /* set sock opts? */
  optval = 1;
  if (setsockopt (sock_info->socket, SOL_SOCKET, SO_REUSEADDR,
                  (void *) &optval, sizeof (optval)) == -1)
    {
      printf ("ERROR: udp_init: setsockopt: %s\n", strerror (errno));
      goto error;
    }


//      if (sock_info->is_lo !=1) {
  if (setsockopt
      (sock_info->socket, SOL_SOCKET, SO_BROADCAST, (void *) &optval,
       sizeof (optval)) != 0)
    {
      printf ("ERROR: udp_init: setsockopt: %s\n", strerror (errno));
      goto error;
    }

  optval = 0;
  if (setsockopt
      (sock_info->socket, IPPROTO_IP, IP_MULTICAST_LOOP, (void *) &optval,
       sizeof (optval)) != 0)
    {
      printf ("ERROR: udp_init: setsockopt: %s\n", strerror (errno));
      goto error;
    }
//      }

//      if ( probe_max_receive_buffer(sock_info->socket)==-1) goto error;

  if (bind (sock_info->socket, (struct sockaddr *) addr, sizeof (*addr)) ==
      -1)
    {
      printf ("ERROR: udp_init: bind(%x, %p, %d) on %s: %s\n",
              sock_info->socket, &addr->sin_addr,
              sizeof (*addr), sock_info->name, strerror (errno));

      goto error;
    }

/*	free(addr);*/
  return 0;

error:
/*	if (addr) free(addr);*/
  return -1;
}



int
udp_rcv_loop ()
{
  unsigned len;

  static char buf[BUF_SIZE + 1];


  struct sockaddr_in *from;
  unsigned int fromlen;


  from = (struct sockaddr_in *) malloc (sizeof (struct sockaddr_in));
  if (from == 0)
    {
      printf ("ERROR: udp_rcv_loop: out of memory\n");
      goto error;
    }
  memset (from, 0, sizeof (struct sockaddr_in));

  for (;;)
    {

      fromlen = sizeof (struct sockaddr_in);
      len =
        recvfrom (bind_address->socket, buf, BUF_SIZE, 0,
                  (struct sockaddr *) from, &fromlen);
      if (len == -1)
        {
          printf ("ERROR: udp_rcv_loop:recvfrom:[%d] %s\n",
                  errno, strerror (errno));
          if ((errno == EINTR) || (errno == EAGAIN) || (errno == EWOULDBLOCK)
              || (errno == ECONNREFUSED))
            continue;           /* goto skip; */
          else
            goto error;
        }
      if (len > 0)
        {

          log_info ("Connect: %s:%d \n", inet_ntoa (from->sin_addr),
                    ntohs (from->sin_port));

          /*debugging, make print* msg work */
          buf[len + 1] = 0;

          /* receive_msg must free buf too! */
          receive_connection (buf, len, from);
          log_flush ();
        }
      else
        {
          log_error ("Error receiving data\n");
        }

      /* skip: do other stuff */

    }
  /*
     if (from) free(from);
     return 0;
   */

error:
  if (from)
    free (from);
  return -1;
}


/* which socket to use? main socket or new one? */
int
udp_send (struct socket_info *source, char *buf, unsigned len,
          struct sockaddr_in *to)
{

  int n;
  int tolen;



  tolen = sizeof (struct sockaddr_in);
again:

  n = sendto (source->socket, buf, len, 0, (struct sockaddr *) to, tolen);
  log_info ("to: %s:%d \n", inet_ntoa (to->sin_addr), ntohs (to->sin_port));
  if (n == -1)
    {
      log_info ("ERROR: udp_send: sendto(sock,%p,%d,0,%p,%d): %s(%d)\n",
                buf, len, to, tolen, strerror (errno), errno);
      if (errno == EINTR)
        goto again;
      if (errno == EINVAL)
        {
          printf ("CRITICAL: invalid sendtoparameters\n"
                  "one possible reason is the server is bound to localhost and\n"
                  "attempts to send to the net\n");
        }
    }
  return n;
}
