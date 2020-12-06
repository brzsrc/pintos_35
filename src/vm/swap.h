#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdbool.h>

/* swap table identifier*/
typedef int sid_t;

void swap_init(void);
void swap_read(sid_t sid, void *page);
sid_t swap_write(void *page);

#endif /* vm/swap.h */