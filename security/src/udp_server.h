

#ifndef udp_server_h
#define udp_server_h

#include <sys/types.h>
#include <sys/socket.h>
#include "ip_addr.h"

#define MAX_RECV_BUFFER_SIZE	256*1024
#define BUFFER_INCREMENT	2048
extern struct socket_info* sendipv4;
extern struct socket_info* bind_address;
extern send_debug_mode;
#define LOG_SEND send_debug_mode

int udp_init(struct socket_info* si);
int udp_send(struct socket_info* source,char *buf, unsigned len,
				struct sockaddr_in*  to);
int udp_rcv_loop();


#endif
