#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stddef.h>

#include "../filesys/off_t.h"
#include "../threads/thread.h"
#include "lib/kernel/hash.h"
<<<<<<< HEAD
#include "filesys/off_t.h"
#include "threads/thread.h"

struct key {
=======

struct who_where {
>>>>>>> 918793ff4fd51ba6510b5036984a6517a92d7692
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
<<<<<<< HEAD
  struct key k;
=======
  struct who_where k;
>>>>>>> 918793ff4fd51ba6510b5036984a6517a92d7692

  // value: essential details to load a segment
  struct load_page_detail load_details;
};

<<<<<<< HEAD
void spmtpt_init(void);
=======
// init
void spmtpt_init(void);

>>>>>>> 918793ff4fd51ba6510b5036984a6517a92d7692
#endif