#ifndef ADHOC_MSG_H
#define ADHOC_MSG_H

#define MSG_REG  0
#define MSG_REP  1
#define MSG_CERT 2
#define MSG_OTH  3

#include <netdb.h>

#include "iobuf.h"
#include "mpi.h"
#include "ip_addr.h"
#include "globals.h"


#ifndef EXTERN_UNLESS_MAIN_MODULE
  #ifndef INCLUDED_BY_MAIN_MODULE
     #define EXTERN_UNLESS_MAIN_MODULE extern
  #else
     #define EXTERN_UNLESS_MAIN_MODULE
  #endif
#endif

extern message_debug_mode;
#define LOG_MSG message_debug_mode

#define BODYREG 1
#define BODYID  2
#define BODYADD 3
#define BODYKEY 4

#define EV_SIG       1
#define EV_SIGREP    2
#define EV_PART      3
#define EV_PART_OK   4
#define EV_PART_LIST 5
#define EV_PART_ADD  6
#define EV_PART_KEY  7
#define EV_ADDR      8

#define EV_SIG_STR       "Signature\r\n"
#define EV_SIGREP_STR    "Signature_Reply\r\n"
#define EV_PART_STR      "Partial\r\n"
#define EV_PART_OK_STR   "Partial_OK\r\n"
#define EV_PART_LIST_STR "Partial_ID_List\r\n"
#define EV_PART_ADD_STR  "Partial_Add_Number\r\n"
#define EV_PART_KEY_STR  "Partial_Key\r\n"
#define EV_ADDR_STR      "Address\r\n"

#define EV_SIG_LEN       11
#define EV_SIGREP_LEN    17
#define EV_PART_LEN       9
#define EV_PART_OK_LEN   12
#define EV_PART_LIST_LEN 17
#define EV_PART_ADD_LEN  20
#define EV_PART_KEY_LEN  13
#define EV_ADDR_LEN       9

struct reg_body {
/* user address data */
    char* user;
    size_t user_len;

/* ip address data */
    char* ip;
    size_t ip_len;

/* port number */
    uint16_t port;

/* public key */
    char* public_key;
    size_t pk_len;
};

struct id_body {
    int num;
    uint32_t id[MAXSPLIT];
};

struct add_body {
    int num;
    MPI adder[MAXSPLIT/2];
};

struct key_body {
    int length;
    char* radmsg;
};

struct body_msg {
    int type;
    union {
	struct reg_body* regbody;
	struct id_body*  idbody;
	struct add_body* addbody;
	struct key_body* keybody;
    } msg;
};

struct sip_msg {
  unsigned int id;               /* message id, unique/process*/
     
  unsigned int type;
  unsigned int outgoing;
  struct ip_addr src_ip;
  struct ip_addr dst_ip;

  char* orig;       /* original message copy */
  char* buf;        /* scratch pad, holds a modfied message,
                     *  via, etc. point into it
                     */

  char* to;
  char* from;
  char* req;
  char* via1;
  char* via2;
    int evt;

  unsigned int hdr_len;
  unsigned int hdr_len2;

  char* body;  /* unsigned message */
  unsigned int body_len;
  char* sign;  /* Signed message, we put it in iobuf */
  unsigned int sign_len;

  char *notsign; /* unsigned message, from outside */
  unsigned int notsign_len;

  unsigned int len; /* message len (orig) */        
  unsigned int buflen; /* buffer length */

  int sips; // 1 for sips message and 0 for other
};




#endif /* ADHOC_MSG_H */
