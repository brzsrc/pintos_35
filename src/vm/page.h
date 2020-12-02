#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stddef.h>

#include "threads/thread.h"
#include "filesys/off_t.h"
#include "lib/kernel/hash.h"

enum upage_status {
    ALL_ZERO,
    LOAD_FILE,
    SWAP
};

struct load_page_detail {
  struct file *file;
  size_t page_read_bytes;
  size_t page_zero_bytes;
  bool writable;
  off_t current_offset;
};

/* the entry in the supplymental page table */
struct spmt_pt_entry {
  struct hash_elem hash_elem;
  enum upage_status status;

  block_sector_t sector;
  struct frame_node *frame_node;

  void *upage;
  void *kpage;

  // value: essential details to load a segment
  struct load_page_detail *load_details;
};

void spmtpt_init(struct hash *spmt_pt);
struct spmt_pt_entry *spmtpt_entry_init(void *upage, void *kpage, enum upage_status status);
void spmtpt_load_details_init(struct load_page_detail *details, struct file *file, 
    size_t page_read_bytes, size_t page_zero_bytes, bool writable, off_t current_offset);
void spmtpt_entry_free(struct spmt_pt_entry *spmtpt_entry);
struct spmt_pt_entry *spmtpt_lookup_entry(struct thread *t, void *upage);
bool spmtpt_load_file(struct spmt_pt_entry *entry);
bool install_page(void *upage, void *kpage, bool writable);
void spmtpt_destroy(struct hash_elem *elem, void *aux UNUSED);
#endif