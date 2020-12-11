#include "vm/swap.h"

#include <debug.h>
#include <stdio.h>

#include "devices/block.h"
#include "kernel/bitmap.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

#define SECTOR_NUM (PGSIZE / BLOCK_SECTOR_SIZE)

struct block *swap_table;
struct bitmap *swap_bitmap;
struct lock swap_bitmap_lock;

struct rw_detail {
  struct semaphore rw_complete;
  sid_t sid;
  void *kpage;
  bool isWrite;
};

/* Initialise swap table. */
void swap_init(void) {
  swap_table = block_get_role(BLOCK_SWAP);
  swap_bitmap = bitmap_create(block_size(swap_table) / SECTOR_NUM);
  lock_init(&swap_bitmap_lock);
}

static void fill_in_rw_details(struct rw_detail *detail, bool isWrite,
                               void *kpage, sid_t sid) {
  detail->isWrite = isWrite;
  detail->kpage = kpage;
  detail->sid = sid;
  sema_init(&detail->rw_complete, 0);
}

static void swap_async_read(void *read_details_) {
  struct rw_detail *read_details = read_details_;
  ASSERT(!read_details->isWrite);
  thread_set_nice(10);
  thread_set_priority(PRI_DEFAULT - 1);
  for (size_t i = 0; i < SECTOR_NUM; i++) {
    block_read(swap_table, read_details->sid * SECTOR_NUM + i,
               read_details->kpage + BLOCK_SECTOR_SIZE * i);
  }
  sema_up(&read_details->rw_complete);
}

/* Read from swap table. */
void swap_read(sid_t sid, void *kpage) {
  struct rw_detail rd;
  fill_in_rw_details(&rd, false, kpage, sid);
  thread_create("read from swap", PRI_DEFAULT, swap_async_read, &rd);
  sema_down(&rd.rw_complete);

  bitmap_reset(swap_bitmap, sid);
};

static void swap_async_write(void *write_details_) {
  struct rw_detail *write_details = write_details_;
  ASSERT(write_details->isWrite);
  thread_set_nice(-10);
  thread_set_priority(PRI_DEFAULT + 1);
  for (size_t i = 0; i < SECTOR_NUM; i++) {
    block_write(swap_table, write_details->sid * SECTOR_NUM + i,
                write_details->kpage + BLOCK_SECTOR_SIZE * i);
  }
  sema_up(&write_details->rw_complete);
}

/* Write to swap table, and return swap id. */
sid_t swap_write(void *kpage) {
  lock_acquire(&swap_bitmap_lock);
  sid_t sid = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
  lock_release(&swap_bitmap_lock);
  ASSERT((unsigned)sid != BITMAP_ERROR);

  struct rw_detail wd;
  fill_in_rw_details(&wd, true, kpage, sid);
  thread_create("write to swap", PRI_DEFAULT, swap_async_write, &wd);
  sema_down(&wd.rw_complete);

  return sid;
}

void swap_free(sid_t sid) { bitmap_reset(swap_bitmap, sid); }

/* For debugging */
// void dump_page(void *addr) {
//     int size = PGSIZE;
//     printf("Memory address %p\n", addr);
//     printf("0\t");
//     while (size-- > 0) {
//         printf("0x%x ", *((uint8_t*)addr));
//         addr++;
//         if (size % 64 == 0) {
//             printf("\n%d\t", size / 64);
//         }
//     }
// }