#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* lookup children in children_list */
struct child * lookup_child(tid_t cpid, struct thread *curr);

/* file descriptor structure that holds information regarding a fd
   Will be contained within the open_fds list for any thread that opens a file */
struct fd
{
  int fd;
  struct file *file;
  struct thread *thread;
  struct list_elem elem; 
};

/* load status */
enum load_status 
{
  FAILED = -1,
  LOADED = 0,
  LOADING = 1,
};

/* structure which contains information of a child
   and lies in the children_list of the parent     */
struct child
{
  int status;
  tid_t cpid;
  bool waited;
  bool exited;
  struct list_elem elem;
};

#endif /* userprog/process.h */
