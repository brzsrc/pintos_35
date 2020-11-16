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

// Do not add them into header file because no one else is
// going to use them
// void syscall_halt(void);
// void syscall_exit(int status);

// These are not yet commented out to suppress warnings
pid_t syscall_exec(const char *cmd_line);
int syscall_wait(pid_t pid);
void syscall_seek(int fd, unsigned position);
unsigned syscall_tell(int fd);
void syscall_close(int fd);

#endif /* userprog/syscall.h */
