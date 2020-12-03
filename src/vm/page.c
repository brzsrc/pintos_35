#include "vm/page.h"

#include <string.h>

#include "filesys/file.h"
#include "page.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "vm/frame.h"

// #include "swap.h"

static unsigned spmtpt_hash(const struct hash_elem *spmtpt_, void *aux UNUSED);
static bool spmtpt_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED);
static void spmtpt_entry_free(struct spmt_pt_entry *spmtpt_entry);
static bool load_from_swap(struct spmt_pt_entry *e, struct thread *t);
static bool load_from_file(struct spmt_pt_entry *e);
static bool install_page(struct spmt_pt_entry *e, void *kpage);

void spmtpt_init(struct hash *spmt_pt) {
  hash_init(spmt_pt, spmtpt_hash, spmtpt_less, NULL);
}

// Malloc. Since we assert non null, returned is always a valid pointer
struct spmt_pt_entry *spmtpt_entry_init(void *upage, enum upage_status status,
                                        struct thread *t) {
  struct spmt_pt_entry *entry =
      (struct spmt_pt_entry *)malloc(sizeof(struct spmt_pt_entry));

  ASSERT(entry != NULL);

  entry->upage = upage;
  entry->status = status;
  entry->t = t;
  return entry;
}

void spmtpt_load_details(struct spmt_pt_entry *e, size_t page_read_bytes,
                         size_t page_zero_bytes, bool writable,
                         off_t current_offset) {
  e->current_offset = current_offset;
  e->page_read_bytes = page_read_bytes;
  e->page_zero_bytes = page_zero_bytes;
  e->writable = writable;
}

/*Find and return the entry if t->upage is valid addr. Otherwise return NULL*/
struct spmt_pt_entry *spmtpt_find(struct thread *t, void *upage) {
  struct spmt_pt_entry entry;
  struct hash_elem *elem;
  entry.upage = upage;
  elem = hash_find(&t->spmt_pt, &entry.hash_elem);
  return elem != NULL ? hash_entry(elem, struct spmt_pt_entry, hash_elem)
                      : NULL;
}

bool spmtpt_load_page(struct spmt_pt_entry *e) {
  if (!e) {
    return false;
  }
  if (e->status == IN_FILE) {
    return load_from_file(e);
  }
  // else if (e->status == IN_SWAP)
  // {
  //   return load_from_swap(e, t);
  // }
  return false;
}

bool spmtpt_zero_page_init(void *upage, struct thread *t) {
  struct spmt_pt_entry *entry =
      (struct spmt_pt_entry *)malloc(sizeof(struct spmt_pt_entry));

  ASSERT(entry != NULL);
  entry->status = ALL_ZERO;
  entry->is_dirty = false;
  entry->upage = upage;
  entry->t = t;

  if (hash_insert(&t->spmt_pt, &entry->hash_elem) == NULL) return true;
  return false;
}

// static bool load_from_swap(struct spmt_pt_entry *e, struct thread *t) {
//   swap_out(e);
// }

static bool load_from_file(struct spmt_pt_entry *e) {
  /* Check if virtual page already allocated */
  uint8_t *kpage = pagedir_get_page(e->t->pagedir, e->upage);
  if (kpage == NULL) {
    // TODO change palloc to frame alloc
    // kpage = palloc_get_page(PAL_USER);
    kpage = frame_alloc(PAL_USER, e, e->t);
    if (kpage == NULL) {
      return false;
    }

    /* Add the page to the process's address space. */
    if (!install_page(e, kpage)) {
      NOT_REACHED();
      palloc_free_page(kpage);
      return false;
    }

    /* Load data into the page. */
    file_sync_seek(e->t->file, e->current_offset);
    if (file_sync_read(e->t->file, kpage, e->page_read_bytes) !=
        (int)e->page_read_bytes) {
      NOT_REACHED();
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + e->page_read_bytes, 0, e->page_zero_bytes);
    e->status = IN_FRAME;
    return true;
  } else {
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

static void spmtpt_entry_free(struct spmt_pt_entry *spmtpt_entry) {
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
