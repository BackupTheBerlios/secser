#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "config.h"

void error (const char* cause, const char* message)
{
/* Print an error message to stderr. */
    fprintf (stderr, "%s: error: (%s) %s\n", PACKAGE, cause, message);
/* End the program. */
    exit (1);
}

void system_error (const char* operation)
{
/* Generate an error message for errno. */
    error (operation, strerror (errno));
}

#ifndef HAVE_STRLWR
char *
strlwr(char *s)
{
    char *p;
    for(p=s; *p; p++ )
        *p = tolower(*p);
    return s;
}
#endif 


