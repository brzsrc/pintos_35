#ifndef USERPROG
#define USERPROG
#endif
#ifndef FILESYS
#define FILESYS
#endif

#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "lib/stdio.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"

struct opened_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};

struct opened_file *get_opened_file(int fd);
static void syscall_handler(struct intr_frame *);

static int get_syscall_number(struct intr_frame *f) { return 0; };

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void check_valid_pointer(void *pointer) {
  if (!is_user_vaddr(pointer) ||
      ((pagedir_get_page(thread_current()->pagedir), pointer) == NULL))
    syscall_exit(-1);
}

static void syscall_handler(struct intr_frame *f) {
  printf("system call!\n");
  int sys_call_no = get_syscall_number(f);

  thread_exit();
}

void syscall_halt(void) { shutdown_power_off(); }

void syscall_exit(int status) {
  thread_current()->status = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

// haven't impelemented synchronization yet
// let pid = tid
pid_t syscall_exec(const char *cmd_line) { return process_execute(cmd_line); }

// haven't completed yet
int syscall_wait(pid_t pid) { return process_wait(pid); }

bool syscall_create(const char *file, unsigned initial_size) {
  return filesys_create(file, initial_size);
}

bool syscall_remove(const char *file) { return filesys_remove(file); }

int syscall_open(const char *file_name) {
  struct file *file = filesys_open(file_name);
  if (!file) {
    return -1;
  }

  struct opened_file *opened_file = palloc_get_page(PAL_ZERO);
  if (!opened_file) {
    return -1;
  }

  opened_file->file = file;
  struct list *opened_files = &thread_current()->opened_files;

  if (list_empty(opened_files)) {
    opened_file->fd = 2;
  } else {
    opened_file->fd =
        list_entry(list_back(opened_files), struct opened_file, elem)->fd + 1;
  }
  list_push_back(opened_files, &opened_file->elem);

  return opened_file->fd;
}

int syscall_filesize(int fd) {
  struct opened_file *opened_file = get_opened_file(fd);

  if (!opened_file) {
    return -1;
  }
  return file_length(opened_file->file);
}

int syscall_read(int fd, void *buffer, unsigned size) {
  if (fd == STDIN_FILENO) {
    for (unsigned int i = 0; i < size; i++) {
      *(uint8_t *)(buffer + i) = input_getc();
    }
    return (int)size;
  }

  struct opened_file *opened_file = get_opened_file(fd);
  if (!opened_file) {
    return -1;
  }

  return file_read(opened_file->file, buffer, size);
}

int syscall_write(int fd, const void *buffer, unsigned size) {
  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    return size;
  }

  struct opened_file *opened_file = get_opened_file(fd);
  if (!opened_file) {
    return -1;
  }

  return file_write(opened_file->file, buffer, size);
}

void syscall_seek(int fd, unsigned position) {
  struct opened_file *opened_file = get_opened_file(fd);

  if (!opened_file) {
    return;
  }

  file_seek(opened_file->file, position);
}

unsigned syscall_tell(int fd) {
  struct opened_file *opened_file = get_opened_file(fd);

  if (!opened_file) {
    return -1;
  }

  return file_tell(opened_file->file);
}

void syscall_close(int fd) {
  struct opened_file *opened_file = get_opened_file(fd);
  if (!opened_file) {
    return;
  }

  file_close(opened_file->file);
  list_remove(&opened_file->elem);
  palloc_free_page(opened_file);
}

struct opened_file *get_opened_file(int fd) {
  struct list *opened_files = &thread_current()->opened_files;
  struct list_elem *e;
  if (list_empty(opened_files)) {
    return NULL;
  }

  for (e = list_begin(opened_files); e != list_end(opened_files);
       e = list_next(e)) {
    struct opened_file *opened_file = list_entry(e, struct opened_file, elem);
    if (opened_file->fd == fd) {
      return opened_file;
    }
  }
  return NULL;
}
