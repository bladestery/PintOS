#include <stdbool.h>
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
bool check_uaddr (const void *uaddr);
#endif /* userprog/syscall.h */
