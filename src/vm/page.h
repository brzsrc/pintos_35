#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stddef.h>

#include "../filesys/off_t.h"
#include "../threads/thread.h"
#include "lib/kernel/hash.h"
#include "filesys/off_t.h"
#include "threads/thread.h"

struct key {
  tid_t tid;
  void *upage;
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

  // key: thread->tid + *upage, identify which user and which uaddr
  struct key k;

  void *upage;
  void *kpage;

  // value: essential details to load a segment
  struct load_page_detail load_details;
};

void spmtpt_init(void);
#endif