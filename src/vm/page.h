#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stddef.h>

#include "filesys/off_t.h"
#include "lib/kernel/hash.h"
#include "threads/thread.h"

enum upage_status { ALL_ZERO, LOAD_FILE, SWAP };

struct load_page_detail {
  // struct file *file; //no need, it is already stored in t->file
  size_t page_read_bytes;
  size_t page_zero_bytes;
  bool writable;
  off_t current_offset;
};

/* the entry in the supplymental page table */
struct spmt_pt_entry {
  struct hash_elem hash_elem;
  enum upage_status status;

  // key: The requested page
  void *upage;
  void *kpage;

  // value: essential details to load a segment
  struct load_page_detail *load_details;
};

void spmtpt_init(struct hash *spmt_pt);
struct hash_elem *spmtpt_insert(struct hash *hash, struct spmt_pt_entry *entry);

struct spmt_pt_entry *spmtpt_find(struct thread *t, void *upage);

struct spmt_pt_entry *spmtpt_entry_init(void *upage, void *kpage,
                                        enum upage_status status);
void spmtpt_load_details_init(struct load_page_detail *details,
                              struct file *file, size_t page_read_bytes,
                              size_t page_zero_bytes, bool writable,
                              off_t current_offset);
// To be called in process exit
void spmtpt_free(struct hash *spmt_pt);

// void spmtpt_entry_free(struct spmt_pt_entry *spmtpt_entry);
// bool spmtpt_load_file(struct spmt_pt_entry *entry);
// bool install_page(void *upage, void *kpage, bool writable);
#endif