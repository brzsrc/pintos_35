#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler(struct intr_frame *);

static int get_syscall_number(struct intr_frame *f UNUSED) { return 0; };

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f) {
  printf("system call!\n");
  int sys_call_no = get_syscall_number(f);
  
  thread_exit();
}

static void syscall_halt() {}
static void syscall_exit() {}
static void syscall_exec() {}
static void syscall_wait() {}
static void syscall_create() {}
static void syscall_remove() {}
static void syscall_open() {}
static void syscall_file_size() {}
static void syscall_read() {}
static void syscall_write() {}
static void syscall_seek() {}
static void syscall_tell() {}
static void syscall_close() {}