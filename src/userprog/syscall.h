#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

#include "lib/user/syscall.h"
#include "lib/kernel/list.h"

struct opened_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};

void syscall_init(void);

#endif /* userprog/syscall.h */
