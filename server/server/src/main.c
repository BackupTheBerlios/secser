#include <config.h>
#include <assert.h>
#include <getopt.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/ipc.h>


#define INCLUDED_BY_MAIN_MODULE 1
#include "globals.h"
#include "util.h"
#include "ip_addr.h"
#include "udp_server.h"
#include "adhoc.h"
#include "options.h"
#include "msg.h"
#include "parser.h"
#include "systemsign.h"
#include "semaphore.h"

/* Description of long options */

static const struct option long_options[] = {
  {"address", 1, NULL, 'a'},
  {"cert", 0, NULL, 'c'},
  {"help", 0, NULL, 'h'},
  {"log", 1, NULL, 'l'},
  {"port", 1, NULL, 'p'},
  {"verbose", 0, NULL, 'v'},
};

/* Description of short options */

static const char *const short_options = "a:chl:p:v";

/* Usage summary text */

static const char *const usage_help =
  "Usage: %s [ options ]\n"
  "  -a, --address ADDR            Bind to local address (by default, bind\n"
  "                                  to all local addresses).\n"
  "  -c, --cert                    Use this option if you have certificate\n"
  "                                  directly from the dealer\n"
  "  -h, --help                    Print this information\n"
  "  -l, --log FILE                Set log to file specified in FILE.\n"
  "  -p, --port PORT               Bind to specified port. (default 4050). \n"
  "  -v, --verbose                 Print verbose messages.\n";


/* -----Variables definition----- */

struct socket_info sock_info[MAX_LISTEN];       /*all addresses we listen/send from */
int sock_no = 0;                /* number of addresses/open sockets */
uint16_t port_no = 0;
int verbose = 0;
int g10_errors_seen = 0;
FILE *routefp;
STRLIST locaddr = NULL;
char *userid = NULL;
char *passwd = NULL;
int message_debug_mode;
int send_debug_mode;
int sip_port = 0;
int numpart = 6;

/* -----End of variables definition----- */

static void
print_usage (int is_error)
{
  fprintf (is_error ? stderr : stdout, usage_help, PACKAGE);
  exit (is_error ? 1 : 0);
}


add_address (uint32_t address, unsigned short port, int is_lo)
{
  char *tmp;

  sock_info[sock_no].address.s_addr = address;
  sock_info[sock_no].port_no = port;
  tmp = inet_ntoa (sock_info[sock_no].address);
  sock_info[sock_no].name = (char *) malloc (strlen (tmp) + 1);
  strncpy (sock_info[sock_no].name, tmp, strlen (tmp) + 1);
  //add_to_strlist2 (&locaddr, sock_info[sock_no].name, 0);
  sock_info[sock_no].is_lo = is_lo;
  sock_no++;
}

/* Get all local IP address */
int
get_local_address (unsigned short port)
{
  struct ifconf ifc;
  struct ifreq *ifr;
  struct ifreq ifrcopy;
  unsigned char addr[4];
  int s, ret;
  char *last;
  int size;
  int lastlen;
  char *tmp;



#define family AF_INET

#ifdef HAVE_SOCKADDR_SA_LEN
#ifndef MAX
#define MAX(a,b) ( ((a)>(b))?(a):(b))
#endif
#endif

  s = socket (family, SOCK_DGRAM, 0);
  ret = (-1);
  lastlen = 0;
  ifc.ifc_req = 0;
  for (size = 10;; size *= 2)
    {
      ifc.ifc_len = size * sizeof (struct ifreq);
      ifc.ifc_req = (struct ifreq *) malloc (size * sizeof (struct ifreq));
      if (ifc.ifc_req == 0)
        {
          fprintf (stderr, "memory allocation failure\n");
          goto error;
        }
      if (ioctl (s, SIOCGIFCONF, &ifc) == -1)
        {
          if (errno == EBADF)
            return 0;           /* invalid descriptor => no such ifs */
          fprintf (stderr, "ioctl failed: %s\n", strerror (errno));
          goto error;
        }
      if ((lastlen) && (ifc.ifc_len == lastlen))
        break;                  /*success,
                                   len not changed */
      lastlen = ifc.ifc_len;
      /* try a bigger array */
      free (ifc.ifc_req);
    }

  last = (char *) ifc.ifc_req + ifc.ifc_len;
  for (ifr = ifc.ifc_req; (char *) ifr < last;
       ifr = (struct ifreq *) ((char *) ifr + sizeof (ifr->ifr_name) +
#ifdef  HAVE_SOCKADDR_SA_LEN
                               MAX (ifr->ifr_addr.sa_len,
                                    sizeof (struct sockaddr))
#else
                               ((ifr->ifr_addr.sa_family == AF_INET) ?
                                sizeof (struct sockaddr_in) :
                                ((ifr->ifr_addr.sa_family == AF_INET6) ?
                                 sizeof (struct sockaddr_in6) : sizeof (struct
                                                                        sockaddr)))
#endif
       ))
    {

      memcpy (addr, &((struct sockaddr_in *) &(ifr->ifr_addr))->sin_addr, 4);
      if (sock_no < (MAX_LISTEN - 1))
        {
          if ((tmp = ip_addr2a (addr, AF_INET)) == 0)
            goto error;
          sock_info[sock_no].name = (char *) m_alloc (strlen (tmp) + 1);
          if (sock_info[sock_no].name == 0)
            {
              fprintf (stderr, "Out of memory.\n");
              goto error;
            }
          strncpy (sock_info[sock_no].name, tmp, strlen (tmp) + 1);
          //add_to_strlist2 (&locaddr, sock_info[sock_no].name, 0); 
          sock_info[sock_no].port_no = port;
          if (ifrcopy.ifr_flags & IFF_LOOPBACK)
            sock_info[sock_no].is_lo = 1;

          inet_aton (sock_info[sock_no].name, &(sock_info[sock_no].address));
          sock_no++;
          ret = 0;
        }
      else
        {
          fprintf (stderr, "Too many addresses (max %d)\n", MAX_LISTEN);
          goto error;
        }

    }

  /* broadcast listen */
  add_address (INADDR_BROADCAST, port, 0);
  free (ifc.ifc_req);           /*clean up */
  close (s);
  return ret;
error:
  if (ifc.ifc_req)
    free (ifc.ifc_req);
  close (s);
  return -1;
}

int
main_parse_cfg ()
{
  FILE *fp = NULL;
  char line[1024];

  fp = fopen (ADHOC_HOMEDIR DIRSEP_S USRCFGFILE, "r");
  if (!fp)
    {
      printf ("Error opening usercfg.txt file\n");
      exit (1);
    }

  while (fgets (line, 1023, fp))
    {
      char *endkeyword;
      char *p;
      size_t keylen;
      size_t valuelen;


      if (*line && line[strlen (line) - 1] != '\n')
        {
          printf ("Line too long\n");
          break;
        }
      if (strlen (line) < 10)
        {
          printf ("Line too short\n");
          break;
        }

      /* remove begining space */
      for (p = line; isspace (*(byte *) p); p++)
        ;
      endkeyword = (char *) strchr (p, ':');
      keylen = endkeyword - p;
      endkeyword++;

      for (; isspace (*(byte *) endkeyword); endkeyword++)
        ;
      valuelen = strlen (line) - (endkeyword - line);

      if (!userid && !(strncasecmp (p, "UserID", keylen)))
        {
          userid = malloc (valuelen);
          if (!userid)
            log_fatal ("Can not allocate memory for userid\n");

          strncpy (userid, endkeyword, valuelen);
          userid[valuelen - 1] = '\0';

        }

      if (!passwd && !(strncasecmp (p, "Password", keylen)))
        {
          passwd = malloc (valuelen);
          if (!passwd)
            log_fatal ("Can not allocate memory for password\n");
          strncpy (passwd, endkeyword, valuelen);
          passwd[valuelen - 1] = '\0';

        }

      if (!sip_port && !(strncasecmp (p, "SipPort", keylen)))
        {
          char *tmp;
          sip_port = 1;
          for (tmp = endkeyword; tmp < endkeyword + (valuelen - 1); tmp++)
            {
              if ((*tmp - '0') <= 9 && (*tmp - '0') >= 0)
                sip_port = sip_port * 10 + (*tmp - 48);
              else
                {
                  log_error ("Error while changing port to number\n");
                  exit (1);
                }
            }
        }
      if (!(strncasecmp (p, "NumPart", keylen)))
        {
          char *tmp;
          numpart = 0;
          for (tmp = endkeyword; tmp < endkeyword + (valuelen - 1); tmp++)
            {
              if ((*tmp - '0') <= 9 && (*tmp - '0') >= 0)
                numpart = numpart * 10 + (*tmp - 48);
              else
                {
                  log_error ("Error while processing number of partial certificate\n");
                  exit (1);
                }
            }
          if (numpart == 0)
            {
               log_error ("Error: NumPart is zero\n");
               exit (1);
            }
        }
      if (!(strncasecmp (p, "LogParser", keylen)))
        {
          char *tmp;
          LOG_PARSER = 0;
          for (tmp = endkeyword; tmp < endkeyword + (valuelen - 1); tmp++)
            {
              if (*tmp == 'd')
                LOG_PARSER++;
            }
        }
      if (!(strncasecmp (p, "LogMsg", keylen)))
        {
          char *tmp;
          LOG_MSG = 0;
          for (tmp = endkeyword; tmp < endkeyword + (valuelen - 1); tmp++)
            {
              if (*tmp == 'd')
                LOG_MSG++;
            }
        }
      if (!(strncasecmp (p, "LogSend", keylen)))
        {
          char *tmp;
          LOG_SEND = 0;
          for (tmp = endkeyword; tmp < endkeyword + (valuelen - 1); tmp++)
            {
              if (*tmp == 'd')
                LOG_SEND++;
            }
        }
    }
  fclose (fp);
  if (!userid || !passwd)
    {
      printf ("Error parsing user configuration file\n");
      exit (1);
    }
}

int
main_run ()
{
  int i, j;
  pid_t pid;

  for (i = 0; i < sock_no; i++)
    {
      printf ("listen on : %s %x %u\n", sock_info[i].name,
              sock_info[i].address.s_addr, sock_info[i].port_no);
      udp_init (&sock_info[i]);
      if (!sendipv4 && !(sock_info[i].is_lo == 1))
        sendipv4 = (&sock_info[i]);
    }

  for (i = 0; i < sock_no; i++)
    {
      for (j = 0; j < CHILD_PER_SOCK; j++)
        {
          if ((pid = fork ()) < 0)
            {
              printf ("main_loop: Cannot fork\n");
              exit (0);
            }
          else if (pid == 0)
            {
              /* child */
              bind_address = &sock_info[i];
              close (STDIN_FILENO);
              //close (STDOUT_FILENO);
              return udp_rcv_loop ();
            }
          else
            {
              /* parents */
            }
        }

    }
  initialize_signal ();
  for (;;)
    {
      /* This is loop for parents */
      pause ();
    }

  return 0;
}

/* We need the home directory also in some other directories, so make
   sure that both variables are always in sync. */
static void
set_homedir (char *dir)
{
  if (!dir)
    dir = "";
  g10_opt_homedir = opt.homedir = dir;
}

int
main (int argc, char **argv)
{
  struct in_addr local_address;
  int next_option;
  char *logname = NULL;
  char *trustdb_name;
  int rc;
  int all_addr = 1;
  char *tmpaddr;
  STRLIST tmplist;
  struct stat tmpstat;
  int port = 4050;
  int has_cert = 0;

  /* read user configuration file */
  main_parse_cfg ();
  if (!sip_port)
    sip_port = 5060;
  printf ("log message = %d\n", LOG_MSG);
  /* initialize key system */
  init ("adhoc");
  set_homedir (ADHOC_HOMEDIR);

  /* Set defaults for options. Bind the server to all local address,
     and assign 4050 port automatically. */

  local_address.s_addr = INADDR_ANY;
  port_no = (uint16_t) htons (port);
  /* Not in verbose mode */
  verbose = 0;

  /* Parse options */
  do
    {
      next_option =
        getopt_long (argc, argv, short_options, long_options, NULL);
      switch (next_option)
        {
        case 'a':
          /* User specified -a or --address. */
          {
            struct hostent *local_host_name;

            /* Look up the hostname the user spesified. */
            local_host_name = gethostbyname (optarg);
            if (local_host_name == NULL || local_host_name->h_length == 0)
              /* Could not resolve the name. */
              error (optarg, "invalid host name");
            else
              /* Hostname is OK, so we can use it */
              sock_info[sock_no].address.s_addr =
                *((int *) (local_host_name->h_addr_list[0]));
          }
          break;

        case 'c':
          has_cert = 1;
          break;

        case 'h':
          /* User specified -h or --help */
          print_usage (0);

        case 'l':
          /* User specified -l or --log */
          {
            logname = strdup (optarg);
          }
          break;

        case 'p':
          /* User specified -p or --port */
          {

            char *end;

            port = strtol (optarg, &end, 10);
            if (*end != '\0')
              /* User specified nondigits in the port number. */
              print_usage (1);
            /* The port number needs to be converted to network byte order. */
            port_no = (uint16_t) htons (port);
          }
          break;

        case 'v':
          /* User specified -v or --verbose */
          verbose = 1;
          break;

        case '?':
          /* User specified an unrecognized option. */
          print_usage (1);

        case -1:
          /* Done with options. */
          break;

        default:
          abort ();
        }
    }
  while (next_option != -1);

  /* We need no more options. Issue an error if the user specified any. */
  if (optind != argc)
    print_usage (1);

  /* get all possible address or the one listed by the user */
  if (all_addr)
    get_local_address (port);
  else
    {
      sock_info[sock_no].port_no = port;
      sock_info[sock_no].name = inet_ntoa (sock_info[sock_no].address);
      /* add localhost */
      add_address (0x100007f, port, 1);
      /* add broadcast address */
      add_address (INADDR_BROADCAST, port, 0);
    }



  /* Prepare for the log file */
  if (!logname)
    /* Set to standard logfile */
    logname = strdup ("adhoc.log");
  log_set_pid (getpid ());
  log_set_name (PACKAGE);
  /* Set log to a file, not stdout or stderr */
  log_set_logfile (logname, 3);

  /* Preparing trustdb, secring and pubring */
  secmem_init (16384);          /* Initializing secure memory */
  keydb_add_resource ("secring" EXTSEP_S "gpg", 0, 1);  /* add secure ring resource */
  keydb_add_resource ("pubring" EXTSEP_S "gpg", 0, 0);  /* add public ring resource */
  //rc = setup_trustdb( 1, ADHOC_HOMEDIR DIRSEP_C "trustdb" EXTSEP_S "gpg" ); /* initialize trust dbname */
  rc = setup_trustdb (1, ".adhoc/trustdb.gpg");
  if (rc)
    log_error ("failed to initialize the TrustDB: %s\n", g10_errstr (rc));

  /* initializing semaphore */
  semapid = semget (IPC_PRIVATE, SEMAPNUM,
                    IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR);
  if (!(semapid == -1))
    semaphore_initialize (semapid, SEMAPNUM);
  else
    log_fatal ("Can not create semaphore\n");

  /* prepare for routing file */
  routefp = fopen ("route.txt", "w+");
  if (!routefp)
    log_fatal ("Can not open routing file\n");
  fclose (routefp);

  /* delete if there is old file from previous run */
  if (!has_cert && (stat (ADHOC_HOMEDIR DIRSEP_S CERTFILE, &tmpstat) == 0))
    unlink (ADHOC_HOMEDIR DIRSEP_S CERTFILE);
  if (!has_cert && (stat (ADHOC_HOMEDIR DIRSEP_S PARTFILE, &tmpstat) == 0))
    unlink (ADHOC_HOMEDIR DIRSEP_S PARTFILE);

  /* delete temporary file at the beginning */
  if (stat (ADHOC_HOMEDIR DIRSEP_S TMPCERTFILE, &tmpstat) == 0)
    unlink (ADHOC_HOMEDIR DIRSEP_S TMPCERTFILE);
  if (stat (ADHOC_HOMEDIR DIRSEP_S IDLISTFILE, &tmpstat) == 0)
    unlink (ADHOC_HOMEDIR DIRSEP_S IDLISTFILE);
  if (stat (ADHOC_HOMEDIR DIRSEP_S ADDERFILE, &tmpstat) == 0)
    unlink (ADHOC_HOMEDIR DIRSEP_S ADDERFILE);
  if (stat (ADHOC_HOMEDIR DIRSEP_S KEYFILE, &tmpstat) == 0)
    unlink (ADHOC_HOMEDIR DIRSEP_S KEYFILE);



  /* Run the server. */
  main_run ();
  return 0;
}
