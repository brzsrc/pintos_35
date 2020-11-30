#include <debug.h>
#include <random.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "frame.h"

struct hash frame_table;

static unsigned frame_hash (const struct hash_elem *f_, void *aux UNUSED);
static bool frame_less (const struct hash_elem *a_, const struct hash_elem *b_,
                void *aux UNUSED);

/* Returns a hash value for frame_node f. */
static unsigned
frame_hash (const struct hash_elem *f_, void *aux UNUSED) {
    const struct frame_node *f = hash_entry (f_, struct frame_node, hash_elem);
    return hash_bytes (&f->kpage, sizeof f->kpage); 
}


/* Returns true if frame a precedes frame b. */
static bool
frame_less (const struct hash_elem *a_, const struct hash_elem *b_,
                void *aux UNUSED)
{
    const struct frame_node *a = hash_entry (a_, struct frame_node, hash_elem); 
    const struct frame_node *b = hash_entry (b_, struct frame_node, hash_elem);
    return a->kpage < b->kpage; 
}
