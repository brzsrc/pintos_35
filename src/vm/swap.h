#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdbool.h>

/* swap table identifier*/
typedef int sid_t;

void swap_init(void);
void swap_read(sid_t sid, void *upage);
sid_t swap_write(void *upage);
void swap_free (sid_t sid);

#endif /* vm/swap.h */