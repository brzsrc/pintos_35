#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

struct child {
    tid_t child_tid;
    struct list_elem elem;
    int exit_status;

    bool terminated;
    bool parent_terminated;

    struct semaphore wait_sema;
};

struct file_child{
    struct child *child;
    char *fn_copy;
};

tid_t process_execute(const char *file_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(void);

#endif /* userprog/process.h */
