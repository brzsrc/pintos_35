#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stddef.h>

#include "../threads/palloc.h"
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include "vm/page.h"
#include "vm/swap.h"

struct frame_node {
  void *kpage;
  void *upage;
  struct thread *t;
  // bool pinned;

  struct lock lock;  // Modification lock
  struct hash_elem hash_elem;
};

void frame_init(void);
struct frame_node *frame_alloc(enum palloc_flags pflag,
                               struct spmt_pt_entry *e);
struct frame_node *frame_find(void *kpage);
void frame_node_free(void *kpage);
#endif /* vm/frame.h */
