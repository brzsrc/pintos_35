#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdbool.h>

/* swap table identifier*/
typedef int sid_t;

void swap_init(void);
void swap_in(struct spmt_pt_entry *e);
bool swap_out(struct spmt_pt_entry *e);

#endif /* vm/swap.h */