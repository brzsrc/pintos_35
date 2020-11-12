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

struct opened_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};

// Function pointers to syscall functions
typedef void (*syscall_func)(void *arg1, void *arg2, void *arg3);

struct lock filesys_lock;

static void check_valid_pointer(void *pointer);
static int get_syscall_number(struct intr_frame *f);
static struct opened_file *get_opened_file(int fd);

static void syscall_handler(struct intr_frame *);
static void syscall_halt(void *, void *, void *);
static void syscall_exit(void *, void *, void *);

static syscall_func syscall_functions[MAX_SYSCALL_NO + 1];

static void check_valid_pointer(void *pointer) {
  struct thread *t = thread_current();
  if (!is_user_vaddr(pointer) ||
      pagedir_get_page(t->pagedir, pointer) == NULL) {
    t->status = -1;
    printf("%s: exit(%d)\n", t->name, t->status);
    thread_exit();
  }
}

static int get_syscall_number(struct intr_frame *f) {
  // DEBUG
  printf("getting syscall no\n");
  void *stack_ptr = f->esp;
  check_valid_pointer(stack_ptr);
  int sys_call_no = *(int *)stack_ptr;
  // DEBUG
  printf("syscall no is %d\n", sys_call_no);
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

void syscall_init(void) {
  lock_init(&filesys_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  // Initialize the array such that handlers can be
  // retrived by indexing into the array using the handler name
  syscall_functions[SYS_HALT] = syscall_halt;
  syscall_functions[SYS_EXIT] = syscall_exit;
}

static void syscall_handler(struct intr_frame *f) {
  // DEBUG
  printf("system call!\n");
  int sys_call_no = get_syscall_number(f);
  void *arg1 = f->esp + 1;  // Does this move to (esp + 4 bytes)?
  void *arg2 = f->esp + 2;
  void *arg3 = f->esp + 3;
  // DEBUG
  printf("Dispatching a function!\n");
  syscall_func function = syscall_functions[sys_call_no];
  function(arg1, arg2, arg3);
  thread_exit();
}

static void syscall_halt(void *arg1 UNUSED, void *arg2 UNUSED,
                         void *arg3 UNUSED) {
  shutdown_power_off();
}

static void syscall_exit(void *arg1, void *arg2 UNUSED, void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  int status = *(int *)arg1;
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
