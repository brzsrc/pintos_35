#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stddef.h>

#include "filesys/off_t.h"
#include "lib/kernel/hash.h"
#include "threads/thread.h"
#include "devices/block.h"

extern struct lock exec_lock;

enum upage_status {
    ALL_ZERO,
    IN_FILE,
    IN_SWAP,
    IN_FRAME
};

/* the entry in the supplymental page table */
struct spmt_pt_entry {
  struct hash_elem hash_elem;
  enum upage_status status;
  bool is_dirty;

  block_sector_t sector;

  void *upage;
  struct thread *t;

  // value: essential details to load a segment
  size_t page_read_bytes;
  size_t page_zero_bytes;
  bool writable;
  off_t current_offset;
};

void spmtpt_init(struct hash *spmt_pt);
struct hash_elem *spmtpt_insert(struct hash *hash, struct spmt_pt_entry *entry);

struct spmt_pt_entry *spmtpt_find(struct thread *t, void *upage);

struct spmt_pt_entry *spmtpt_entry_init(void *upage,
                                        enum upage_status status, struct thread *t);
void spmtpt_load_details(struct spmt_pt_entry *e,
                              size_t page_read_bytes,
                              size_t page_zero_bytes, bool writable,
                              off_t current_offset);
// To be called in process exit
void spmtpt_free(struct hash *spmt_pt);
bool spmtpt_load_page(struct spmt_pt_entry *e);
bool spmtpt_zero_page_init(void *upage, struct thread *t);
#endif