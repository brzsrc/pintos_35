#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/stdio.h"
#include "pagedir.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

// Function pointers to syscall functions
typedef unsigned int (*syscall_func)(void *arg1, void *arg2, void *arg3);

struct lock filesys_lock;

static void check_valid_pointer(void *pointer);
static int get_syscall_number(struct intr_frame *f);
static struct opened_file *get_opened_file(int fd);

static void syscall_handler(struct intr_frame *);

static unsigned int syscall_halt(void *, void *, void *);
static unsigned int syscall_exit(void *, void *, void *);
static unsigned int syscall_wait(void *, void *, void *);
static unsigned int syscall_create(void *, void *, void *);
static unsigned int syscall_remove(void *, void *, void *);
static unsigned int syscall_open(void *, void *, void *);
static unsigned int syscall_filesize(void *, void *, void *);
static unsigned int syscall_read(void *, void *, void *);
static unsigned int syscall_write(void *, void *, void *);
static unsigned int syscall_seek(void *, void *, void *);
static unsigned int syscall_tell(void *, void *, void *);
static unsigned int syscall_close(void *, void *, void *);
static syscall_func syscall_functions[MAX_SYSCALL_NO + 1];

void syscall_init(void) {
  lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  // Initialize the array such that handlers can be
  // retrived by indexing into the array using the handler name
  syscall_functions[SYS_HALT] = syscall_halt;
  syscall_functions[SYS_EXIT] = syscall_exit;
  syscall_functions[SYS_WAIT] = syscall_wait;

  syscall_functions[SYS_CREATE] = syscall_create;
  syscall_functions[SYS_REMOVE] = syscall_remove;
  syscall_functions[SYS_OPEN] = syscall_open;
  syscall_functions[SYS_FILESIZE] = syscall_filesize;
  syscall_functions[SYS_READ] = syscall_read;
  syscall_functions[SYS_WRITE] = syscall_write;
  syscall_functions[SYS_SEEK] = syscall_seek;
  syscall_functions[SYS_TELL] = syscall_tell;
  syscall_functions[SYS_CLOSE] = syscall_close;
}

static void check_valid_pointer(void *pointer) {
  struct thread *t = thread_current();
  if (!is_user_vaddr(pointer) ||
      pagedir_get_page(t->pagedir, pointer) == NULL) {
    // TODO Design the pointer validation logic
    printf("Invalid pointer access!\n");
    NOT_REACHED();  // Panic the os to indicate error. Should be replaced by
                    // some handling logic
  }
}

static int get_syscall_number(struct intr_frame *f) {
  void *stack_ptr = f->esp;
  check_valid_pointer(stack_ptr);
  int sys_call_no = *(int *)stack_ptr;
  return sys_call_no;
}

static struct opened_file *get_opened_file(int fd) {
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

static void syscall_handler(struct intr_frame *f) {
  int sys_call_no = get_syscall_number(f);

  void *arg1 = f->esp + 4;
  void *arg2 = f->esp + 8;
  void *arg3 = f->esp + 12;

  syscall_func function = syscall_functions[sys_call_no];

  unsigned int result = function(arg1, arg2, arg3);
  // printf("result of sys call: %x\n", result);
  f->eax = result;
}

// Tested OK
static unsigned int syscall_halt(void *arg1 UNUSED, void *arg2 UNUSED,
                                 void *arg3 UNUSED) {
  shutdown_power_off();
  NOT_REACHED();
  return 0;  // void
}

static unsigned int syscall_exit(void *arg1, void *arg2 UNUSED,
                                 void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  int exit_status = *(int *)arg1;
  struct thread *t = thread_current();
  t->child->exit_status = exit_status;
  printf("%s: exit(%d)\n", t->name, exit_status);
  thread_exit();
  return 0;  // void
}

// let pid = tid
pid_t syscall_exec(const char *cmd_line) { 
  printf("exec");
  lock_acquire(&filesys_lock);
  tid_t tid = process_execute(cmd_line); 
  lock_release(&filesys_lock);
  return tid;
}

// haven't completed yet
static unsigned int syscall_wait(void *arg1, void *arg2 UNUSED,
                                 void *arg3 UNUSED) {
                                   printf("wait");
  pid_t pid = *(pid_t *)arg1;
  return process_wait(pid);  // int
}

// Tested OK
static unsigned int syscall_create(void *arg1, void *arg2, void *arg3 UNUSED) {
  const char *file = *(char **)arg1;
  unsigned int initial_size = *(unsigned int *)arg2;
  lock_acquire(&filesys_lock);
  bool result = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return result;  // bool
}

// Tested OK
static unsigned int syscall_remove(void *arg1, void *arg2 UNUSED,
                                   void *arg3 UNUSED) {
  const char *file = *(char **)arg1;
  lock_acquire(&filesys_lock);
  bool result = filesys_remove(file);
  lock_release(&filesys_lock);
  return result;  // bool
}

// Tested OK
static unsigned int syscall_open(void *arg1, void *arg2 UNUSED,
                                 void *arg3 UNUSED) {
  const char *file_name = *(char **)arg1;
  lock_acquire(&filesys_lock);
  struct file *file = filesys_open(file_name);
  if (!file) {
    lock_release(&filesys_lock);
    return -1;
  }

  struct opened_file *opened_file = malloc(sizeof(struct opened_file));
  if (!opened_file) {
    lock_release(&filesys_lock);
    return -1;
  }

  lock_release(&filesys_lock);

  opened_file->file = file;
  struct list *opened_files = &thread_current()->opened_files;

  if (list_empty(opened_files)) {
    opened_file->fd = 2;
  } else {
    opened_file->fd =
        list_entry(list_back(opened_files), struct opened_file, elem)->fd + 1;
  }
  list_push_back(opened_files, &opened_file->elem);

  return opened_file->fd;  // int
}

// Tested OK
static unsigned int syscall_filesize(void *arg1, void *arg2 UNUSED,
                                     void *arg3 UNUSED) {
  int fd = *(int *)arg1;
  struct opened_file *opened_file = get_opened_file(fd);

  if (!opened_file) {
    return -1;
  }
  lock_acquire(&filesys_lock);
  off_t result = file_length(opened_file->file);
  lock_release(&filesys_lock);

  return result;  // int
}

static unsigned int syscall_read(void *arg1, void *arg2, void *arg3) {
  int fd = *(int *)arg1;
  void *buffer = *(char **)arg2;
  unsigned int size = *(unsigned int *)arg3;

  if (fd == STDIN_FILENO) {
    for (unsigned int i = 0; i < size; i++) {
      *(uint8_t *)(buffer + i) = input_getc();
    }
    return size;  // int
  }

  lock_acquire(&filesys_lock);
  struct opened_file *opened_file = get_opened_file(fd);
  if (!opened_file) {
    lock_release(&filesys_lock);
    return -1;
  }

  off_t result = file_read(opened_file->file, buffer, size);
  lock_release(&filesys_lock);

  return result;  // int
}

static unsigned int syscall_write(void *arg1, void *arg2, void *arg3) {
  int fd = *(int *)arg1;
  const void *buffer = *(char **)arg2;
  unsigned size = *(unsigned *)arg3;
  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    return size;
  }

  struct opened_file *opened_file;

  lock_acquire(&filesys_lock);
  opened_file = get_opened_file(fd);
  if (!opened_file) {
    lock_release(&filesys_lock);
    return -1;
  }

  lock_acquire(&filesys_lock);
  off_t off = file_write(opened_file->file, buffer, size);
  lock_release(&filesys_lock);
  return off;
}

static unsigned int syscall_seek(void *arg1, void *arg2, void *arg3 UNUSED) {
  int fd = *(int *)arg1;
  unsigned int position = *(unsigned int *)arg2;
  struct opened_file *opened_file;

  lock_acquire(&filesys_lock);
  opened_file = get_opened_file(fd);

  if (!opened_file) {
    lock_release(&filesys_lock);
    return 0;
  } else {
    file_seek(opened_file->file, position);
    lock_release(&filesys_lock);
    return 0;  // void
  }

  lock_acquire(&filesys_lock);
  file_seek(opened_file->file, position);
  lock_release(&filesys_lock);
}

static unsigned int syscall_tell(void *arg1, void *arg2 UNUSED,
                                 void *arg3 UNUSED) {
  int fd = *(int *)arg1;
  struct opened_file *opened_file;
  unsigned int result;

  lock_acquire(&filesys_lock);
  opened_file = get_opened_file(fd);

  if (!opened_file) {
    lock_release(&filesys_lock);
    return 0;
  } else {
    result = file_tell(opened_file->file);
    lock_release(&filesys_lock);
    return result;  // off_t
  }

  lock_acquire(&filesys_lock);
  off_t off = file_tell(opened_file->file);
  lock_release(&filesys_lock);
  return off;
}

static unsigned int syscall_close(void *arg1, void *arg2 UNUSED,
                                  void *arg3 UNUSED) {
  int fd = *(int *)arg1;
  struct opened_file *opened_file;
  opened_file = get_opened_file(fd);
  
  if (!opened_file) {
    return -1;
  }

  lock_acquire(&filesys_lock);
  file_close(opened_file->file);
  lock_release(&filesys_lock);
  list_remove(&opened_file->elem);
  free(opened_file);
  return 0;  // void
}
