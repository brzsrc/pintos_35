#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stddef.h>

#include "../threads/palloc.h"
#include "lib/kernel/hash.h"

struct frame_node {
  void *kpage;
  void *upage;
  struct thread *t;

  struct hash_elem hash_elem;
};

void frame_init(void);
void *frame_alloc(enum palloc_flags pflag, void *upage, struct thread *t);
struct frame_node *frame_find(void *kpage);
void frame_node_free(void *kpage);
#endif /* vm/frame.h */
