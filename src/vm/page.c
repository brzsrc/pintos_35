#include "vm/page.h"

#include <string.h>

#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

static unsigned spmtpt_hash(const struct hash_elem *spmtpt_, void *aux UNUSED);
static bool spmtpt_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED);
static void spmtpt_entry_free(struct spmt_pt_entry *spmtpt_entry);

void spmtpt_init(struct hash *spmt_pt) {
  hash_init(spmt_pt, spmtpt_hash, spmtpt_less, NULL);
}

// Malloc. Since we assert non null, returned is always a valid pointer
struct spmt_pt_entry *spmtpt_entry_init(void *upage, void *kpage,
                                        enum upage_status status) {
  struct spmt_pt_entry *entry =
      (struct spmt_pt_entry *)malloc(sizeof(struct spmt_pt_entry));
  struct load_page_detail *load_details =
      (struct load_page_detail *)malloc(sizeof(struct load_page_detail));

  ASSERT(entry != NULL);
  ASSERT(load_details != NULL);

  entry->upage = upage;
  entry->kpage = kpage;
  entry->status = status;
  entry->load_details = load_details;
  return entry;
}

void spmtpt_load_details_init(struct load_page_detail *details,
                              size_t page_read_bytes,
                              size_t page_zero_bytes, bool writable,
                              off_t current_offset) {
  details->current_offset = current_offset;
  details->page_read_bytes = page_read_bytes;
  details->page_zero_bytes = page_zero_bytes;
  details->writable = writable;
}

struct spmt_pt_entry *spmtpt_find(struct thread *t, void *upage) {
  struct spmt_pt_entry entry;
  struct hash_elem *elem;
  entry.upage = upage;
  elem = hash_find(&t->spmt_pt, &entry.hash_elem);
  return elem != NULL ? hash_entry(elem, struct spmt_pt_entry, hash_elem)
                      : NULL;
}

// /* If we need to load file, then we first alloc one kpage to the upage,
//    then we add the upage and its kpage into pagedir, if success, then we
//    load file into the kpage */
// bool spmtpt_load_file(struct spmt_pt_entry *entry) {
//   void *upage = entry->upage;
//   void *kpage = frame_alloc(PAL_USER, upage);
//   struct load_page_detail *detail = entry->load_details;
//   entry->kpage = kpage;

//   /* Add the page to the process's address space. */
//   if (!install_page(upage, kpage, detail->writable)) {
//     palloc_free_page(kpage);
//     return false;
//   }

//   /* Load data into the page. */
//   if (file_read(detail->file, kpage, detail->page_read_bytes) !=
//       (int)detail->page_read_bytes) {
//     palloc_free_page(kpage);
//     return false;
//   }
//   memset(kpage + detail->page_read_bytes, 0, detail->page_zero_bytes);
//   return true;
// }

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
  free(spmtpt_entry->load_details);
  free(spmtpt_entry);
}