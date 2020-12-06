#include <debug.h>
#include <stdio.h>
#include <bitmap.h>

#include "vm/swap.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/block.h"

#define PAGES (PGSIZE / BLOCK_SECTOR_SIZE)

struct block *swap_table;
struct bitmap *swap_bitmap;
struct lock swap_lock;

/* Initialise swap table. */
void
swap_init(void) {
    swap_table = block_get_role(BLOCK_SWAP);
    if(swap_table == NULL) {
        swap_bitmap = bitmap_create(0);
        printf("Warning - Swap table is empty.\n");
    } else {
        swap_bitmap = bitmap_create(block_size(swap_table) / PAGES);
    }

    if(swap_bitmap == NULL) {
        PANIC("Error - Swap bitmap cannot be created.");
    }

    lock_init(&swap_lock);
}

/* Swap in spmtpt_entry. */
void swap_in(struct spmt_pt_entry *spmtpt_entry) {
    for(size_t i = 0; i < PAGES; i++){
        bitmap_reset(swap_bitmap, spmtpt_entry->sector / PAGES);
        block_read(swap_table, spmtpt_entry->sector + i, spmtpt_entry->upage + BLOCK_SECTOR_SIZE * i);
        spmtpt_entry->sector = -1;
    }
};

/* Swap out spmtpt_entry. */
bool swap_out(struct spmt_pt_entry *spmtpt_entry) {
    spmtpt_entry->sector = bitmap_scan_and_flip(swap_bitmap, 0, 1, false) * PAGES;

    for(size_t i = 0; i < PAGES; i++){
        block_write(swap_table, spmtpt_entry->sector + i, spmtpt_entry->upage + BLOCK_SECTOR_SIZE * i);
    }

    return true;
}