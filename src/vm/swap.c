#include <debug.h>
#include <stdio.h>

#include "vm/swap.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/block.h"
#include "kernel/bitmap.h"

#define SECTOR_NUM (PGSIZE / BLOCK_SECTOR_SIZE)

struct block *swap_table;
struct bitmap *swap_bitmap;
struct lock swap_lock;

/* Initialise swap table. */
void
swap_init(void) {
    swap_table = block_get_role(BLOCK_SWAP);
    swap_bitmap = bitmap_create(block_size(swap_table) / SECTOR_NUM);
    lock_init(&swap_lock);
}

void dump_page(void *addr) {
    int size = PGSIZE;
    printf("Memory address %p\n", addr);
    printf("0\t");
    while (size-- > 0) {
        printf("0x%x ", *((uint8_t*)addr));
        addr++;
        if (size % 64 == 0) {
            printf("\n%d\t", size / 64);
        }
    }
}

/* Read from swap table. */
void 
swap_read(sid_t sid, void *kpage) {
    // lock_acquire(&swap_lock);
    for(size_t i = 0; i < SECTOR_NUM; i++) {
        block_read(swap_table, sid * SECTOR_NUM + i, kpage + (BLOCK_SECTOR_SIZE * i));
    }
    // lock_release(&swap_lock);
    // dump_page(kpage);
    // if(*(uint8_t*)kpage != 0x5a) {
    //     printf("kpage = %p\n", kpage);
    // }
    bitmap_reset (swap_bitmap, sid);
};

/* Write to swap table, and return swap id. */
sid_t
swap_write(void *kpage) {
    sid_t sid = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
    // lock_acquire(&swap_lock);
    // if(*(uint8_t*)kpage != 0x5a) {
    //     printf("kpage = %p\n", kpage);
    // }
    for(size_t i = 0; i < SECTOR_NUM; i++) {
        block_write(swap_table, sid * SECTOR_NUM + i, kpage + (BLOCK_SECTOR_SIZE * i));
    }
    // lock_release(&swap_lock);

    return sid;
}

void
swap_free (sid_t sid)
{
  if (bitmap_test(swap_bitmap, sid))
    return
  bitmap_set(swap_bitmap, sid, true);
}
