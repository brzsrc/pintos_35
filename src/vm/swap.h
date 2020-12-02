#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stdbool.h>

void swap_init(void);
void swap_in(struct spmt_pt_entry *);
bool swap_out(struct spmt_pt_entry *);

#endif /* vm/swap.h */