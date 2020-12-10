#include "frame.h"

#include <debug.h>
#include <random.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "kernel/hash.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

struct hash frame_table;

static unsigned frame_hash(const struct hash_elem *f_, void *aux UNUSED);
static bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_,
                       void *aux UNUSED);
static struct frame_node *frame_find_evict(void);

void frame_init(void) { hash_init(&frame_table, frame_hash, frame_less, NULL); }

struct frame_node *frame_alloc(enum palloc_flags pflag,
                               struct spmt_pt_entry *e) {
  void *palloc_kpage = palloc_get_page(PAL_USER | pflag);
  struct frame_node *frame = NULL;
  if (palloc_kpage == NULL) {
    frame = frame_find_evict();

    ASSERT(frame != NULL);
    ASSERT(frame->kpage != NULL);
    ASSERT(lock_held_by_current_thread(&frame->lock));

    struct spmt_pt_entry *evicted_page =
        spmtpt_find(&frame->t->spmt_pt, frame->upage);

    ASSERT(evicted_page != NULL);

    evicted_page->is_dirty =
        pagedir_is_dirty(frame->t->pagedir, frame->upage) ||
        evicted_page->is_dirty;

    evicted_page->status = IN_SWAP;
    evicted_page->sid = swap_write(frame->kpage);
    evicted_page->kpage = NULL;

    // frame_node_free(evicted_node);
    pagedir_clear_page(evicted_page->t->pagedir, evicted_page->upage);

    frame->upage = e->upage;
    frame->t = e->t;
    e->kpage = frame->kpage;
  } else {
    frame = (struct frame_node *)malloc(sizeof(struct frame_node));
    frame->upage = e->upage;
    frame->kpage = palloc_kpage;
    frame->t = e->t;
    e->kpage = palloc_kpage;
    lock_init(&frame->lock);
    lock_acquire(&frame->lock);
    hash_insert(&frame_table, &frame->hash_elem);
  }
  return frame;
}

static struct frame_node *frame_find_evict(void) {
  struct hash_iterator i;

  hash_first(&i, &frame_table);
  while (hash_next(&i)) {
    struct frame_node *node =
        hash_entry(hash_cur(&i), struct frame_node, hash_elem);
    bool succ = lock_try_acquire(&node->lock);
    if (!succ) continue;

    if (!pagedir_is_accessed(node->t->pagedir, node->kpage)) {
      return node;
    }
    pagedir_set_accessed(node->t->pagedir, node->kpage, false);
    lock_release(&node->lock);
  }
  hash_first(&i, &frame_table);
  struct frame_node *node =
      hash_entry(hash_cur(&i), struct frame_node, hash_elem);
  lock_acquire(&node->lock);
  return node;
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
  if (node) {
    hash_delete(&frame_table, &node->hash_elem);
    if (kpage && kpage != 0xcccccccc) palloc_free_page(kpage);
  }
  free(node);
}

/*Find and return the entry if t->upage is valid addr. Otherwise return NULL*/
struct frame_node *frame_find(void *kpage) {
  struct frame_node node;
  struct hash_elem *elem;
  node.kpage = kpage;
  elem = hash_find(&frame_table, &node.hash_elem);
  return elem != NULL ? hash_entry(elem, struct frame_node, hash_elem) : NULL;
}