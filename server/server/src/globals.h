#ifndef ADHOC_GLOBAL_H
#define ADHOC_GLOBAL_H

#include <sys/types.h>
#include <netdb.h>

#include "config.h"
#include "types.h"

#define MAX_BUF 3040 // maximum receiving buffer
#define MIN_SIG 180  // minimum signature message length
#define MAXSPLIT 10  // maximum splitting number of partial key required
#define FBITS 160 // number of bits to be added to partial secret key
#define MAX_LISTEN  6 // Maximum number of interface we listen to, including localloop & broadcast
#define CHILD_PER_SOCK 2 // Number of child to fork for each interface

/* specified if we use verbose of not */
extern int verbose;

/* list of addresses we listen/send from*/
extern struct socket_info sock_info[]; 

/* Number of addresses/open sockets */
extern int sock_no; 

/* port number we are using */
extern uint16_t port_no;

/* routing file pointer */
extern FILE* routefp;

/* number of parttial certificates needed */
extern int numpart;

#define USRCFGFILE "usercfg.txt"
#define CERTFILE "cert.gpg"
#define TMPCERTFILE ".tmpcert"
#define PUBFILE "syspub.gpg"
#define PARTFILE "partial.gpg"
#define IDLISTFILE ".id.lst"
#define ADDERFILE ".add.lst"
#define KEYFILE ".key.lst"

extern STRLIST locaddr; // list of local address

/* below must be shared memory or held by main */
extern char* userid;

/* number of partial sign required */
#define NUMPART numpart

extern int sip_port;
#define SIP_PORT sip_port // port of sip proxy

#endif /* ADHOC_GLOBAL_H */
