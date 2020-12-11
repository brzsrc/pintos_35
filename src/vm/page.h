#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stddef.h>

#include "devices/block.h"
#include "filesys/off_t.h"
#include "lib/kernel/hash.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "vm/swap.h"

enum upage_status { ALL_ZERO, IN_FILE, IN_SWAP, IN_FRAME };

/* the entry in the supplymental page table */
struct spmt_pt_entry {
  struct hash_elem hash_elem;
  struct list_elem list_elem;
  enum upage_status status;
  bool is_dirty;
  bool writable;

  void *upage;
  void *kpage;
  struct thread *t;

  sid_t sid;

  struct lock modify_lock;

  // value: essential details to load a segment
  size_t page_read_bytes;
  size_t page_zero_bytes;
  off_t current_offset;
  struct file *file;
};

void spmtpt_init(struct hash *spmt_pt);
struct hash_elem *spmtpt_insert(struct hash *hash, struct spmt_pt_entry *entry);

struct spmt_pt_entry *spmtpt_find(struct hash *spmt_pt, void *upage);

bool spmtpt_entry_init(struct spmt_pt_entry *entry, void *upage, bool writable,
                       enum upage_status status, struct thread *t);
void spmtpt_fill_in_load_details(struct spmt_pt_entry *e,
                                 size_t page_read_bytes, size_t page_zero_bytes,
                                 off_t current_offset, struct file *file);

bool load_page_lazy(struct file *file, off_t ofs, uint8_t *upage,
                    size_t page_read_bytes, size_t page_zero_bytes,
                    bool writable, struct spmt_pt_entry **entry);

// To be called in process exit
void spmtpt_free(struct hash *spmt_pt);
bool spmtpt_load_page(struct spmt_pt_entry *e);
void spmtpt_entry_free(struct hash *spmt_pt,
                       struct spmt_pt_entry *spmtpt_entry);
#endif