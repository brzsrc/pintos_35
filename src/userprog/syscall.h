#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

#include "lib/kernel/list.h"
#include "lib/user/syscall.h"

struct opened_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};

struct mmaped_file {
  mapid_t mid;
  struct spmt_pt_entry *entry;
  struct list_elem elem;
};

void syscall_init(void);
void syscall_exit_helper(int exit_status);

#endif /* userprog/syscall.h */
