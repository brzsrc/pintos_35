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

struct hash frame_table;

static unsigned spmtpt_hash(const struct hash_elem *f_, void *aux UNUSED);
static bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_,
                       void *aux UNUSED);

void frame_init() { hash_init(&frame_table, spmtpt_hash, frame_less, NULL); }

void *frame_alloc(enum palloc_flags pflag, void *upage) {
  void *kpage = palloc_get_page(PAL_USER | pflag);
  if (kpage == NULL) {
    // use eviction algorithm to free a kpage in the frame table
  }

  struct frame_node *new_node =
      (struct frame_node *)malloc(sizeof(struct frame_node));
  new_node->upage = upage;
  new_node->kpage = kpage;
  hash_insert(&frame_table, &new_node->hash_elem);
  return kpage;
}

/* Returns a hash value for frame_node f. */
static unsigned spmtpt_hash(const struct hash_elem *f_, void *aux UNUSED) {
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
