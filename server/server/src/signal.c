#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "util.h"
#include "memory.h"
#include "semaphore.h"

static void
clean_up_child_process (int signal_number)
{
  int status;
  wait (&status);

}

static void
got_fatal_signal (int signal_number)
{

  switch (signal_number)
    {
    case SIGINT:
    case SIGTERM:
      {
        kill (0, SIGTERM);
        while (wait (0) > 0);

        secmem_term ();
        semaphore_deallocate (semapid, SEMAPNUM);

        printf ("Thank you for using adhoc\n");
        exit (0);
        break;
      }

    case SIGUSR1:
    case SIGUSR2:
    case SIGHUP:
    case SIGPIPE:
      break;

    default:
      log_info ("unhandle signal\n");
    }
}

void
initialize_signal ()
{
  struct sigaction sigchld_action;
  struct sigaction sigoth_action;

  /* Install a handler for SIGCHLD that cleans up child processes that
     have terminated */

  memset (&sigchld_action, 0, sizeof (sigchld_action));
  sigchld_action.sa_handler = &clean_up_child_process;
  sigaction (SIGCHLD, &sigchld_action, NULL);

  /* create default action for other signal */
  memset (&sigoth_action, 0, sizeof (sigoth_action));
  sigoth_action.sa_handler = &got_fatal_signal;
  sigaction (SIGINT, &sigoth_action, NULL);
  sigaction (SIGTERM, &sigoth_action, NULL);
  sigaction (SIGUSR1, &sigoth_action, NULL);
  sigaction (SIGUSR2, &sigoth_action, NULL);
  sigaction (SIGHUP, &sigoth_action, NULL);
  sigaction (SIGPIPE, &sigoth_action, NULL);
}
