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
#include "vm/page.h"

// Function pointers to syscall functions
typedef unsigned int (*syscall_func)(void *arg1, void *arg2, void *arg3);

// Only one exec at a time
struct lock exec_lock;

static void check_valid_pointer(const void *pointer);
static int get_syscall_number(struct intr_frame *f);
static struct opened_file *get_opened_file(int fd);

static void syscall_handler(struct intr_frame *);

static unsigned int syscall_halt(void *, void *, void *);
static unsigned int syscall_exit(void *, void *, void *);
static unsigned int syscall_exec(void *, void *, void *);
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
static unsigned int syscall_mmap(void *, void *, void *);
static unsigned int syscall_munmap(void *, void *, void *);
static syscall_func syscall_functions[MAX_SYSCALL_NO + 1];
static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);

void syscall_init(void) {
  lock_init(&exec_lock);
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");

  // Initialize the array such that handlers can be
  // retrived by indexing into the array using the handler name
  syscall_functions[SYS_HALT] = syscall_halt;
  syscall_functions[SYS_EXIT] = syscall_exit;
  syscall_functions[SYS_EXEC] = syscall_exec;
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
  syscall_functions[SYS_MMAP] = syscall_mmap;
  syscall_functions[SYS_MUNMAP] = syscall_munmap;
}

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault occurred. */
static int get_user(const uint8_t *uaddr) {
  int result;
  asm("movl $1f, %0; movzbl %1, %0; 1:" : "=&a"(result) : "m"(*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool put_user(uint8_t *udst, uint8_t byte) {
  int error_code;
  asm("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a"(error_code), "=m"(*udst)
      : "q"(byte));
  return error_code != -1;
}

static void check_valid_pointer(const void *pointer) {
  struct thread *t = thread_current();
  if (!pointer || !is_user_vaddr(pointer) || get_user(pointer) == -1) {
    syscall_exit_helper(-1);
  }
}

/* Check arg Non null */
static void check_valid_arg(const void *arg, unsigned int size) {
  const void *temp = arg;
  for (unsigned i = 0; i <= size; i += PGSIZE) {
    check_valid_pointer(temp);
    temp++;
  }
}

static int get_syscall_number(struct intr_frame *f) {
  void *stack_ptr = f->esp;

  check_valid_pointer(stack_ptr);
  int sys_call_no = *(int *)stack_ptr;

  return sys_call_no;
}

// Thread safe because only the thread itself can
// access t->opened_files;
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

  thread_current()->esp = f->esp;
  void *arg1 = f->esp + 4;
  void *arg2 = f->esp + 8;
  void *arg3 = f->esp + 12;

  syscall_func function = syscall_functions[sys_call_no];

  unsigned int result = function(arg1, arg2, arg3);

  f->eax = result;
}

static unsigned int syscall_halt(void *arg1 UNUSED, void *arg2 UNUSED,
                                 void *arg3 UNUSED) {
  shutdown_power_off();
  NOT_REACHED();
  return 0;
}

static unsigned int syscall_exit(void *arg1, void *arg2 UNUSED,
                                 void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  int exit_status = *(int *)arg1;
  syscall_exit_helper(exit_status);
  return 0;
}

void syscall_exit_helper(int exit_status) {
  struct thread *t = thread_current();
  if (t->child) {
    t->child->exit_status = exit_status;
  }
  printf("%s: exit(%d)\n", t->name, exit_status);
  thread_exit();
}

// let pid = tid
static unsigned int syscall_exec(void *arg1, void *arg2 UNUSED,
                                 void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  const char *cmd_line = *(const char **)arg1;
  check_valid_arg(cmd_line, 0);

  lock_acquire(&exec_lock);
  tid_t tid = process_execute(cmd_line);
  lock_release(&exec_lock);
  return tid;
}

static unsigned int syscall_wait(void *arg1, void *arg2 UNUSED,
                                 void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  pid_t pid = *(pid_t *)arg1;

  return process_wait(pid);
}

static unsigned int syscall_create(void *arg1, void *arg2, void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  check_valid_pointer(arg2);
  const char *file = *(char **)arg1;
  unsigned int initial_size = *(unsigned int *)arg2;
  check_valid_arg(file, initial_size);

  bool result = filesys_sync_create(file, initial_size);
  return result;
}

static unsigned int syscall_remove(void *arg1, void *arg2 UNUSED,
                                   void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  const char *file = *(char **)arg1;
  check_valid_arg(file, 0);

  bool result = filesys_sync_remove(file);
  return result;
}

// Tested OK
static unsigned int syscall_open(void *arg1, void *arg2 UNUSED,
                                 void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  const char *file_name = *(char **)arg1;
  check_valid_arg(file_name, 0);

  struct file *file = filesys_sync_open(file_name);
  if (!file) {
    return -1;
  }

  struct opened_file *opened_file = malloc(sizeof(struct opened_file));
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

static unsigned int syscall_filesize(void *arg1, void *arg2 UNUSED,
                                     void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  int fd = *(int *)arg1;

  struct opened_file *opened_file = get_opened_file(fd);

  if (!opened_file) {
    return -1;
  }

  off_t result = file_sync_length(opened_file->file);

  return result;
}

static unsigned int syscall_read(void *arg1, void *arg2, void *arg3) {
  check_valid_pointer(arg1);
  check_valid_pointer(arg2);
  check_valid_pointer(arg3);
  int fd = *(int *)arg1;
  void *buffer = *(char **)arg2;
  unsigned int size = *(unsigned int *)arg3;
  check_valid_arg(buffer, size);

  if (fd == STDIN_FILENO) {
    for (unsigned int i = 0; i < size; i++) {
      *(uint8_t *)(buffer + i) = input_getc();
    }
    return size;
  }

  for (void *upage = pg_round_down(buffer); upage < buffer + size;
       upage += PGSIZE) {
    struct thread *t = thread_current();
    struct spmt_pt_entry *entry = spmtpt_find(t, upage);
    spmtpt_load_page(entry);
  }

  struct opened_file *opened_file = get_opened_file(fd);
  if (!opened_file || !opened_file->file) {
    return -1;
  }

  off_t result = file_read(opened_file->file, buffer, size);

  return result;
}

static unsigned int syscall_write(void *arg1, void *arg2, void *arg3) {
  check_valid_pointer(arg1);
  check_valid_pointer(arg2);
  check_valid_pointer(arg3);
  int fd = *(int *)arg1;
  const void *buffer = *(char **)arg2;
  unsigned size = *(unsigned *)arg3;
  check_valid_arg(buffer, size);

  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    return size;
  }

  struct opened_file *opened_file;

  opened_file = get_opened_file(fd);
  if (!opened_file || !opened_file->file) {
    return -1;
  }

  for (void *upage = pg_round_down(buffer); upage < buffer + size;
       upage += PGSIZE) {
    struct thread *t = thread_current();
    struct spmt_pt_entry *entry = spmtpt_find(t, upage);
    spmtpt_load_page(entry);
  }

  off_t off = file_sync_write(opened_file->file, buffer, size);
  return off;
}

static unsigned int syscall_seek(void *arg1, void *arg2, void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  check_valid_pointer(arg2);
  int fd = *(int *)arg1;
  unsigned int position = *(unsigned int *)arg2;

  struct opened_file *opened_file;

  opened_file = get_opened_file(fd);

  if (!opened_file || !opened_file->file) {
    return 0;
  } else {
    file_seek(opened_file->file, position);
    return 0;
  }
}

static unsigned int syscall_tell(void *arg1, void *arg2 UNUSED,
                                 void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  int fd = *(int *)arg1;

  struct opened_file *opened_file;
  unsigned int result;

  opened_file = get_opened_file(fd);

  if (!opened_file || !opened_file->file) {
    return 0;
  } else {
    result = file_sync_tell(opened_file->file);
    return result;
  }
}

static unsigned int syscall_close(void *arg1, void *arg2 UNUSED,
                                  void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  int fd = *(int *)arg1;

  struct opened_file *opened_file;
  opened_file = get_opened_file(fd);

  if (!opened_file || !opened_file->file) {
    return -1;
  }

  file_sync_close(opened_file->file);

  list_remove(&opened_file->elem);
  free(opened_file);
  return 0;
}

static unsigned int syscall_mmap(void *arg1, void *arg2, void *arg3 UNUSED) {
  check_valid_pointer(arg1);
  check_valid_pointer(arg2);
  int fd = *(int *)arg1;
  void *addr = *(char **)arg2;

  mapid_t mid;

  struct opened_file *opened_file = get_opened_file(fd);
  struct file *file = opened_file->file;
  if (!opened_file || !file || file_length(file) == 0 || addr == 0
                   || fd == STDIN_FILENO || fd == STDOUT_FILENO) {
    return MAP_FAILED;
  }

  return mid;
}

static unsigned int syscall_munmap(void *arg1, void *arg2 UNUSED,
                                  void *arg3 UNUSED) {
  check_valid_pointer(arg1); 
  mapid_t mapping = *(int *)arg1;  
                             
                                  }