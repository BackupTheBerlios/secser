/* This is going to contain function for routing.
 * routing file will be in .adhoc/route.txt.
 * The routing file is a text file with format :
 * 
 * UserAddress	IPAddress	Port */

#include <stdio.h>
#include <stdlib.h>

#include "globals.h"
#include "msg.h"
#include "adhoc.h"
#include "util.h"
#include "semaphore.h"


int
route_add (struct reg_body *body)
{

  char addr[80];
  char ip[16];
  char kar;
  size_t port;
  char all[105] = { 0 };
  STRLIST route = NULL;
  STRLIST rest = NULL;
  STRLIST tmp = NULL;
  int type;

  semaphore_wait (semapid, SEMROUTE);
  routefp = NULL;
  routefp = fopen ("route.txt", "r+");
  if (!routefp)
    {
      semaphore_post (semapid, SEMROUTE);
      return -1;
    }

/* read each line and find match addr */
  while (!feof (routefp))
    {
      type = 0;
      if (fscanf
          (routefp, "%s%c%s%c%u%c", &addr, &kar, &ip, &kar, &port,
           &kar) != EOF)
        {
          if (!strcasecmp (addr, body->user))
            {
              type = 1;
              if (!strcasecmp (ip, body->ip))
                {
                  type = 2;
                  if (port == body->port)
                    {
                      free_strlist (route);
                      //fclose (routefp);
                      semaphore_post (semapid, SEMROUTE);
                      return 0;
                    }
                  else
                    {
                      /* different port number */
                      break;
                    }
                }
              else
                {
                  /* different ip address */
                  break;
                }
            }
          sprintf (all, "%s\t%s\t%u\n\0", addr, ip, port);

          add_to_strlist2 (&route, all, 1);

        }
    }

  if (type == 0)
    {
      /* This only happen if we had read till EOF */
      /* write to routing file first */

      fprintf (routefp, "%s\t%s\t%u\n", body->user, body->ip, body->port);
      fclose (routefp);
      semaphore_post (semapid, SEMROUTE);
      return 1;
    }
  else
    {

      /* something has changed. Read the rest of the file first */
      while (!feof (routefp))
        {
          if (fscanf
              (routefp, "%s%c%s%c%u%c", &addr, &kar, &ip, &kar, &port,
               &kar) != EOF)
            {
              sprintf (all, "%s\t%s\t%u\n\0", addr, ip, port);
              add_to_strlist2 (&rest, all, 0);
            }
        }

      /* close the file and rewrite it */
      fclose (routefp);
      routefp = fopen ("route.txt", "w+");

      /* Write beginning of file */
      for (tmp = route; tmp; tmp = tmp->next)
        {
          fwrite (tmp->d, 1, strlen (tmp->d), routefp);
        }

      /* write changes */
      fprintf (routefp, "%s\t%s\t%u\n", body->user, body->ip, body->port);

      /* Write last part of file */
      for (tmp = rest; tmp; tmp = tmp->next)
        {
          fwrite (tmp->d, 1, strlen (tmp->d), routefp);
        }
      fclose (routefp);
      free_strlist (route);
      free_strlist (rest);
      semaphore_post (semapid, SEMROUTE);
      return 2;
    }
}

int
route_by_address (char *toaddr, char *toip)
{

  char addr[80];
  char ip[16];
  char kar;
  size_t port;
  size_t length;

  semaphore_wait (semapid, SEMROUTE);
  routefp = NULL;
  routefp = fopen ("route.txt", "r");
  if (!routefp)
    {
      semaphore_post (semapid, SEMROUTE);
      return 1;
    }

  while (!feof (routefp))
    {
      if (fscanf
          (routefp, "%s%c%s%c%u%c", &addr, &kar, &ip, &kar, &port,
           &kar) != EOF)
        {
          if (!strcasecmp (addr, toaddr))
            {
              memcpy (toip, ip, 16);
              fclose (routefp);
              semaphore_post (semapid, SEMROUTE);
              return 0;
            }
        }
    }
  fclose (routefp);
  semaphore_post (semapid, SEMROUTE);
  return 1;
}

add_route_from_via (const char *recipient, const char *rec_ip)
{
  char *ip;
  char *addr;
  struct reg_body *body = NULL;

  body = m_alloc (sizeof (*body));
  if (!body)
    return 1;

  ip = m_alloc (strlen (ip) + 1);
  strcpy (ip, rec_ip);

  addr = m_alloc (strlen (recipient) + 1);
  strcpy (addr, recipient);

  body->ip = ip;
  body->user = addr;
  body->port = 4050;            // bad practice to use magic number

  route_add (body);
  m_free (ip);
  m_free (recipient);
  m_free (body);

  return 0;
}
