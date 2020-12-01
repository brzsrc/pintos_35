#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stddef.h>

#include "../threads/palloc.h"
#include "lib/kernel/hash.h"

struct frame_node {
  void *kpage;
  void *upage;

  struct hash_elem hash_elem;
};

void frame_init();
void *frame_alloc(enum palloc_flags pflag, void *upage);
#endif /* vm/frame.h */
