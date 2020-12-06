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
#include "kernel/hash.h"

struct hash frame_table;

static unsigned frame_hash(const struct hash_elem *f_, void *aux UNUSED);
static bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_,
                       void *aux UNUSED);
static struct frame_node *frame_evict(void);

void frame_init(void) { hash_init(&frame_table, frame_hash, frame_less, NULL); }

void *frame_alloc(enum palloc_flags pflag, struct spmt_pt_entry *e) {
  void *kpage = palloc_get_page(PAL_USER | pflag);

  if (kpage == NULL) {
    struct frame_node *evicted_node = frame_evict();
    if(evicted_node == NULL) {
      evicted_node = frame_evict();
    }

    struct spmt_pt_entry *evicted_entry 
      = spmtpt_find(&evicted_node->t->spmt_pt, evicted_node->upage); 

    if(!evicted_entry->is_dirty || !evicted_entry->writable) {
        evicted_entry->status = IN_FILE;
    } else
    {
      evicted_entry->status = IN_SWAP;
      e->sid = swap_write(evicted_node->kpage);
    }

    frame_node_free(evicted_node->kpage);
    pagedir_clear_page(evicted_entry->t->pagedir, evicted_entry->upage);
  }

  struct frame_node *new_node =
      (struct frame_node *)malloc(sizeof(struct frame_node));
  new_node->upage = e->upage;
  new_node->kpage = e->kpage;
  new_node->t = e->t;
  new_node->referenced = true;
  hash_insert(&frame_table, &new_node->hash_elem);
  return kpage;
}

static struct frame_node *frame_evict(void) {
    // somehow get the evicted kpage;
  struct hash_iterator i;

  hash_first (&i, &frame_table);
  while (hash_next (&i))
  {
    struct frame_node *node = hash_entry (hash_cur (&i), struct frame_node, hash_elem);
    if(!node->referenced && !node->pinned) {
      return node;
    } 
    node->referenced = false;
  }
  return NULL;
}

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
  if(node) {
    hash_delete(&frame_table, &node->hash_elem);
    palloc_free_page(kpage);
  }
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