#ifndef ADHOC_SEMAPHORE_H
#define ADHOC_SEMAPHORE_H

#include <sys/sem.h>

/* We must define union semun ourselves. */

union semun {
  int val;
  struct semid_ds *buf;
  unsigned short int *array;
  struct seminfo *__buf;
};

#define SEMTMPCERT 0
#define SEMID      1
#define SEMADD     2
#define SEMKEY     3
#define SEMROUTE   4

#define SEMAPNUM 5 // number of type in above definitions

int semaphore_deallocate (int semid, int num);
int semaphore_initialize (int semid, int num);
int semaphore_wait (int semid, int num);
int semaphore_post (int semid, int num);

extern int semapid;
#endif /* ADHOC_SEMAPHORE_H */
