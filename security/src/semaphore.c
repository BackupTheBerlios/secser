#include <sys/ipc.h>
#include <sys/types.h>

#include "memory.h"
#include "semaphore.h"

int semapid;

/* deallocate semaphore */

int
semaphore_deallocate (int semid, int num)
{
  union semun ignored_argument;
  return semctl (semid, num, IPC_RMID, ignored_argument);
}

int
semaphore_initialize (int semid, int num)
{
  union semun argument;
  unsigned short *values;
  int i;

  values = m_alloc (num * sizeof (*values));
  for (i = 0; i < num; i++)
    values[i] = 1;
  argument.array = values;
  return semctl (semid, 0, SETALL, argument);
}

int
semaphore_wait (int semid, int num)
{
  struct sembuf operations[1];

  /* set only the semaphore that we want */
  operations[0].sem_num = num;
  /*Decrement by 1 */
  operations[0].sem_op = -1;
  /* Permit undo'ing. */
  operations[0].sem_flg = SEM_UNDO;

  return semop (semid, operations, 1);
}

int
semaphore_post (int semid, int num)
{
  struct sembuf operations[1];

  /* set only the semaphore that we want */
  operations[0].sem_num = num;
  /* increment by 1 */
  operations[0].sem_op = 1;
  /* Permit undo'ing */
  operations[0].sem_flg = SEM_UNDO;

  return semop (semid, operations, 1);
}
