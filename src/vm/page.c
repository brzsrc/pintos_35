#include "vm/page.h"

#include <stdio.h>
#include <string.h>

#include "filesys/file.h"
#include "page.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"

static unsigned spmtpt_hash(const struct hash_elem *spmtpt_, void *aux UNUSED);
static bool spmtpt_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED);
// static bool load_from_swap(struct spmt_pt_entry *e, struct thread *t);
static bool load_from_file(struct spmt_pt_entry *e);
static bool install_page(struct spmt_pt_entry *e, void *kpage);
static bool load_all_zero(struct spmt_pt_entry *e);
static bool load_from_swap_table(struct spmt_pt_entry *e);

void spmtpt_init(struct hash *spmt_pt) {
  hash_init(spmt_pt, spmtpt_hash, spmtpt_less, NULL);
}

/**
 * Fill in details in entry and then insert entry into t->spmt_pt
 * Returns whether insertion is successful
 */
bool spmtpt_entry_init(struct spmt_pt_entry *entry, void *upage, bool writable,
                       enum upage_status status, struct thread *t) {
  ASSERT(entry != NULL);

  entry->upage = upage;
  entry->status = status;
  entry->t = t;
  entry->is_dirty = false;
  entry->writable = writable;
  entry->sid = -1;

  if (spmtpt_insert(&t->spmt_pt, entry) != NULL) {
    // There exists an identical entry
    return false;
  }
  return true;
}

// fill in details in e
void spmtpt_fill_in_load_details(struct spmt_pt_entry *e,
                                 size_t page_read_bytes, size_t page_zero_bytes,
                                 off_t current_offset, struct file *file) {
  e->current_offset = current_offset;
  e->page_read_bytes = page_read_bytes;
  e->page_zero_bytes = page_zero_bytes;
  e->file = file;
}

/*Find and return the entry if t->upage is valid addr. Otherwise return NULL*/
struct spmt_pt_entry *spmtpt_find(struct hash *spmt_pt, void *upage) {
  struct spmt_pt_entry entry;
  struct hash_elem *elem;
  entry.upage = upage;
  elem = hash_find(spmt_pt, &entry.hash_elem);
  return elem != NULL ? hash_entry(elem, struct spmt_pt_entry, hash_elem)
                      : NULL;
}

/**
 * Load frame into RAM according to e
 * Return false if e is null, or load is not successful
 */
bool spmtpt_load_page(struct spmt_pt_entry *e) {
  if (!e) {
    return false;
  }

  switch (e->status) {
    case IN_FILE:
      return load_from_file(e);

    case IN_FRAME:
      break;

    case IN_SWAP:
      return load_from_swap_table(e);

    case ALL_ZERO:
      return load_all_zero(e);

    default:
      break;
  }
  return false;
}

// static bool load_from_swap(struct spmt_pt_entry *e, struct thread *t) {
//   swap_out(e);
// }

static bool load_from_swap_table(struct spmt_pt_entry *e) {
  void *kpage = frame_alloc(PAL_USER, e);
  if (kpage == NULL) {
    return false;
  }

  /* Add the page to the process's address space. */
  if (!install_page(e, kpage)) {
    NOT_REACHED();
    spmtpt_entry_free(&e->t->spmt_pt, e);
    frame_node_free(kpage);
    return false;
  }

  swap_read(e->sid, kpage);
  e->status = IN_FRAME;
  e->kpage = kpage;
  e->sid = -1;
  return true;
}

static bool load_all_zero(struct spmt_pt_entry *e) {
  void *kpage = frame_alloc(PAL_ZERO, e);
  if (kpage == NULL) {
    return false;
  }

  /* Add the page to the process's address space. */
  if (!install_page(e, kpage)) {
    NOT_REACHED();
    spmtpt_entry_free(&e->t->spmt_pt, e);
    frame_node_free(kpage);
    return false;
  }

  memset(kpage, 0, PGSIZE);
  e->status = IN_FRAME;
  e->kpage = kpage;
  e->sid = -1;
  return true;
}

static bool load_from_file(struct spmt_pt_entry *e) {
  /* Check if virtual page already allocated */
  uint8_t *kpage = pagedir_get_page(e->t->pagedir, e->upage);
  if (kpage == NULL) {
    kpage = frame_alloc(PAL_USER, e);
    if (kpage == NULL) {
      return false;
    }

    /* Add the page to the process's address space. */
    if (!install_page(e, kpage)) {
      NOT_REACHED();
      spmtpt_entry_free(&e->t->spmt_pt, e);
      frame_node_free(kpage);
      return false;
    }

    /* Load data into the page. */
    file_sync_seek(e->file, e->current_offset);
    if (file_sync_read(e->file, kpage, e->page_read_bytes) !=
        (int)e->page_read_bytes) {
      NOT_REACHED();
      spmtpt_entry_free(&e->t->spmt_pt, e);
      frame_node_free(kpage);
      return false;
    }

    memset(kpage + e->page_read_bytes, 0, e->page_zero_bytes);
    e->status = IN_FRAME;
    e->kpage = kpage;
    e->sid = -1;
    return true;
  } 
  else {
    // Something went wrong
    NOT_REACHED();
    return false;
  }
}

/* Use entry->upage as the key for hash */
static unsigned spmtpt_hash(const struct hash_elem *spmtpt_, void *aux UNUSED) {
  const struct spmt_pt_entry *spmtpt =
      hash_entry(spmtpt_, struct spmt_pt_entry, hash_elem);
  return hash_bytes(&spmtpt->upage, sizeof spmtpt->upage);
}

/* Returns true if spmt_pt_entry a precedes spmt_pt_entry b. */
static bool spmtpt_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED) {
  const struct spmt_pt_entry *a =
      hash_entry(a_, struct spmt_pt_entry, hash_elem);
  const struct spmt_pt_entry *b =
      hash_entry(b_, struct spmt_pt_entry, hash_elem);
  return a->upage < b->upage;
}

struct hash_elem *spmtpt_insert(struct hash *spmtpt,
                                struct spmt_pt_entry *entry) {
  struct hash_elem *e;
  e = hash_insert(spmtpt, &entry->hash_elem);
  return e;
}

void spmtpt_free(struct hash *spmt_pt) {
  // TODO free every entry and free the struct hash
  // hash_destroy(spmt_pt, free_spmtpt_entry);
  return;
}

void spmtpt_entry_free(struct hash *spmt_pt,
                       struct spmt_pt_entry *spmtpt_entry) {
  // TODO
  // Should use frame alloc free page
  hash_delete(spmt_pt, &spmtpt_entry->hash_elem);
  free(spmtpt_entry);
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(struct spmt_pt_entry *e, void *kpage) {
  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(e->t->pagedir, e->upage) == NULL &&
          pagedir_set_page(e->t->pagedir, e->upage, kpage, e->writable));
}

/* Lazily Loads a page starting at offset OFS in FILE at address
   UPAGE.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true and sets entry to e if successful, false if a memory allocation
   error or disk read error occurs. */
bool load_page_lazy(struct file *file, off_t ofs, uint8_t *upage,
                    size_t page_read_bytes, size_t page_zero_bytes,
                    bool writable, struct spmt_pt_entry **entry) {
  ASSERT(pg_ofs(upage) == 0);

  off_t current_offset = ofs;

  /* Check if virtual page already allocated */
  struct thread *t = thread_current();
  struct spmt_pt_entry *e =
      (struct spmt_pt_entry *)malloc(sizeof(struct spmt_pt_entry));

  // There must not be any identical entry
  if (!spmtpt_entry_init(e, upage, writable, IN_FILE, t)) {
    spmtpt_entry_free(&e->t->spmt_pt, e);
    return false;
  }

  spmtpt_fill_in_load_details(e, page_read_bytes, page_zero_bytes,
                              current_offset, file);

  *entry = e;
  return true;
}