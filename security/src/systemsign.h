#ifndef SYSTEMSIGN_H
#define SYSTEMSIGN_H

#include "iobuf.h"

int systemsign_sign (char* output, char* inpbuf, unsigned length);
int systemsign_join (char* buf, unsigned buflen, uint32_t remoteaddr);
PKT_signature* systemsign_get_signature (char* filename, IOBUF data);
void systemsign_sigversion_to_magic (MD_HANDLE md, const PKT_signature *sig);

#endif /* SYSTEMSIGN_H */
