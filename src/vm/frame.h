#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <stddef.h>
#include "lib/kernel/hash.h"

struct frame_node {
    void *kpage;
    void *upage;

    struct hash_elem hash_elem;
}

#endif /* vm/frame.h */
