#include <string.h>

#include "vm/page.h"
#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"

static unsigned spmtpt_hash(const struct hash_elem *spmtpt_, void *aux UNUSED);
static bool spmtpt_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED);

void spmtpt_init(struct hash *spmt_pt) {
  hash_init(spmt_pt, spmtpt_hash, spmtpt_less, NULL);
}

// Malloc
struct spmt_pt_entry *spmtpt_entry_init(void *upage, void *kpage,
                                        enum upage_status status) {
  struct spmt_pt_entry *entry =
      (struct spmt_pt_entry *)malloc(sizeof(struct spmt_pt_entry));
  struct load_page_detail *load_details =
      (struct load_page_detail *)malloc(sizeof(struct load_page_detail));
  entry->upage = upage;
  entry->kpage = kpage;
  entry->status = status;
  entry->load_details = load_details;
  return entry;
}

void spmtpt_load_details_init(struct load_page_detail *details,
                              struct file *file, size_t page_read_bytes,
                              size_t page_zero_bytes, bool writable,
                              off_t current_offset) {
  details->current_offset = current_offset;
  details->file = file;
  details->page_read_bytes = page_read_bytes;
  details->page_zero_bytes = page_zero_bytes;
  details->writable = writable;
}

void spmtpt_entry_free(struct spmt_pt_entry *spmtpt_entry) {
  free(spmtpt_entry->load_details);
  free(spmtpt_entry);
}

//haven't finished yet
void spmtpt_destroy(struct hash_elem *elem, void *aux UNUSED) {
  struct spmt_pt_entry *e = hash_entry (elem, struct spmt_pt_entry, hash_elem);
  free (e);
}

struct spmt_pt_entry *spmtpt_lookup_entry(struct thread *t, void *upage) {
  struct spmt_pt_entry entry;
  struct hash_elem *elem;
  entry.upage = upage;
  elem = hash_find(&t->spmt_pt, &entry.hash_elem);
  return elem != NULL ? hash_entry(elem, struct spmt_pt_entry, hash_elem)
                      : NULL;
}

/* If we need to load file, then we first alloc one kpage to the upage,
   then we add the upage and its kpage into pagedir, if success, then we
   load file into the kpage */
bool spmtpt_load_file(struct spmt_pt_entry *entry) {
  void *upage = entry->upage;
  void *kpage = frame_alloc(PAL_USER, upage);
  struct load_page_detail *detail = entry->load_details;
  entry->kpage = kpage;

  /* Add the page to the process's address space. */
  if (!install_page(upage, kpage, detail->writable)) {
    palloc_free_page(kpage);
    return false;
  }

  /* Load data into the page. */
  if (file_read(detail->file, kpage, detail->page_read_bytes) !=
      (int)detail->page_read_bytes) {
    palloc_free_page(kpage);
    return false;
  }
  memset(kpage + detail->page_read_bytes, 0, detail->page_zero_bytes);
  return true;
}

/* Returns a hash value for frame_node f. */
static unsigned spmtpt_hash(const struct hash_elem *spmtpt_, void *aux UNUSED) {
  const struct spmt_pt_entry *spmtpt =
      hash_entry(spmtpt_, struct spmt_pt_entry, hash_elem);
  return hash_bytes(&spmtpt->upage, sizeof spmtpt->upage);
}

/* Returns true if frame a precedes frame b. */
static bool spmtpt_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED) {
  const struct spmt_pt_entry *a =
      hash_entry(a_, struct spmt_pt_entry, hash_elem);
  const struct spmt_pt_entry *b =
      hash_entry(b_, struct spmt_pt_entry, hash_elem);
  return a->upage < b->upage;
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
bool install_page(void *upage, void *kpage, bool writable) {
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pagedir, upage) == NULL &&
          pagedir_set_page(t->pagedir, upage, kpage, writable));
}