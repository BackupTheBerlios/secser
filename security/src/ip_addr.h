#ifndef ADHOC_IP_ADDR_H
#define ADHOC_IP_ADDR_H

#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define BUF_SIZE 3040

struct ip_addr{
        unsigned int af; /* address family: AF_INET6 or AF_INET */
        unsigned int len;    /* address len, 16 or 4 */

        /* 64 bits alligned address */
        union {
                unsigned int   addr32[4];
                unsigned short addr16[8];
                unsigned char  addr[16];
        }u;
};



struct net{
        struct ip_addr ip;
        struct ip_addr mask;
};




struct socket_info{
        int socket;
        char* name; /* name - eg.: foo.bar or 10.0.0.1 */
        struct in_addr address; /* ip address */
        
        unsigned short port_no;  /* port number */
        char* port_no_str; /* port number converted to string -- optimization*/

        int is_ip; /* 1 if name is an ip address, 0 if not  -- optimization*/
        int is_lo; /* 1 if is a loopback, 0 if not */
        struct sockaddr_in sockin;
};

/***** ip_addr.h *****/
char* ip_addr2a(unsigned char *ip, int type);






#endif /* ADHOC_IP_ADDR_H */
