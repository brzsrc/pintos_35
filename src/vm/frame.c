#include "frame.h"

#include <debug.h>
#include <random.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "page.h"
// #include "swap.h"

struct hash frame_table;

static unsigned frame_hash(const struct hash_elem *f_, void *aux UNUSED);
static bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_,
                       void *aux UNUSED);

void frame_init(void) { hash_init(&frame_table, frame_hash, frame_less, NULL); }

void *frame_alloc(enum palloc_flags pflag, void *upage, struct thread *t) {
  void *kpage = palloc_get_page(PAL_USER | pflag);
//   if (kpage == NULL) {
//     // use eviction algorithm to get a kpage to be evicted in the frame table
//     //write the algorithm in func frame_evict();
//     //...
//     // struct frame_node *evicted_node = frame_evict();
//     struct frame_node *evicted_node;
//     struct spmt_pt_entry *evicted_entry = spmtpt_find(evicted_node->t, evicted_node->upage); 
//     if(!evicted_entry->is_dirty || !evicted_entry->writable) {
//         evicted_entry->status = IN_FILE;
//     } else
//     {
//         evicted_entry->status = IN_SWAP;
//         // swap_in(evicted_entry);
//     }
//     //frame_delete_node: delete the evicted_node in frame
//     //padedir delete the evicted_node
//   }

  struct frame_node *new_node =
      (struct frame_node *)malloc(sizeof(struct frame_node));
  new_node->upage = upage;
  new_node->kpage = kpage;
  new_node->t = t;
  hash_insert(&frame_table, &new_node->hash_elem);
  return kpage;
}

// struct frame_node *frame_evict() {
//     // somehow get the evicted kpage;

// }

/* Returns a hash value for frame_node f. */
static unsigned frame_hash(const struct hash_elem *f_, void *aux UNUSED) {
  const struct frame_node *f = hash_entry(f_, struct frame_node, hash_elem);
  return hash_bytes(&f->kpage, sizeof f->kpage);
}

/* Returns true if frame a precedes frame b. */
static bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_,
                       void *aux UNUSED) {
  const struct frame_node *a = hash_entry(a_, struct frame_node, hash_elem);
  const struct frame_node *b = hash_entry(b_, struct frame_node, hash_elem);
  return a->kpage < b->kpage;
}

void frame_node_free(void *kpage) {
  struct frame_node *node = frame_find(kpage);
  hash_delete(&frame_table, &node->hash_elem);
  palloc_free_page(kpage);
  free(node);
}

/*Find and return the entry if t->upage is valid addr. Otherwise return NULL*/
struct frame_node *frame_find(void *kpage) {
  struct frame_node node;
  struct hash_elem *elem;
  node.kpage = kpage;
  elem = hash_find(&frame_table, &node.hash_elem);
  return elem != NULL ? hash_entry(elem, struct frame_node, hash_elem)
                      : NULL;
}