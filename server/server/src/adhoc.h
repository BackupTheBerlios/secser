#ifndef ADHOC_ADHOC_H
#define ADHOC_ADHOC_H

#include <netinet/in.h>
#include <sys/types.h>

#include "config.h"
#include "util.h"
#include "msg.h"
#include "packet.h"

/***** common.c *****/
void system_error (const char* operation);
void error (const char* cause, const char* message);
#ifndef HAVE_STRLWR
char * strlwr(char *s);
#endif



/***** server.c *****/
int receive_connection (char* buffer, unsigned bytes_read, struct sockaddr_in* from);

/***** process.c *****/
int process_sign_package (struct sip_msg *msg, STRLIST locusr, STRLIST recipient, int orig);
int process_verify_package (struct sip_msg* msg);
int process_create_reg_body (struct sip_msg* msg, STRLIST locusr, STRLIST recipient);
int process_reg_response (struct sip_msg* msg, STRLIST locusr, STRLIST recipient);
void process_generate_adder (MPI* adder, int num);
int process_remove_via (struct sip_msg* msg);
int process_insert_via (struct sip_msg* msg);

/***** parser.c *****/
char* parser_create_address (char* address, int from, int sips);
int parse_msg (struct sip_msg* msg, STRLIST* locusr, STRLIST* recipient);
int parse_body (char* buffer, int length, struct body_msg* body);
char* parser_create_req (char* buff);
int parse_via_header (struct sip_msg *msg, char ip[]);

/***** route.c *****/
int route_add (struct reg_body* body);
int route_by_address (char* toaddr, char* toip);
int add_route_from_via (const char* recipient, const char* rec_ip);

/***** handle.c *****/
int handle_cert (struct sip_msg* msg, STRLIST locusr, STRLIST recipient, uint32_t remoteaddr);

/***** interpolate.c *****/
MPI interpolate (MPI* y, PKT_public_key* pk, MPI hash, uint32_t* x, unsigned num);
void sort (uint32_t* x, MPI* y, unsigned num);

/***** signal.c *****/
void initialize_signal ();

/***** initfunc.c *****/
void i18n_init(void);
void init (char* logname);
void g10_exit( int rc );

extern int g10_errors_seen;

#endif /* ADHOC_ADHOC_H */
