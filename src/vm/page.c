#include "page.h"

static unsigned spmtpt_hash(const struct hash_elem *spmtpt_, void *aux UNUSED);
static bool spmtpt_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED);

void spmtpt_init(struct hash *spmt_pt) { 
    hash_init(spmt_pt, spmtpt_hash, spmtpt_less, NULL); 
}

void spmtpt_entry_init(struct spmt_pt_entry *entry, ) {
    entry
}

/* Returns a hash value for frame_node f. */
static unsigned spmtpt_hash(const struct hash_elem *spmtpt_, void *aux UNUSED) {
  const struct spmt_pt_entry *spmtpt =
      hash_entry(spmtpt_, struct spmt_pt_entry, hash_elem);
  return hash_bytes(&spmtpt->kpage, sizeof spmtpt->kpage);
}

/* Returns true if frame a precedes frame b. */
static bool spmtpt_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED) {
  const struct spmt_pt_entry *a =
      hash_entry(a_, struct spmt_pt_entry, hash_elem);
  const struct spmt_pt_entry *b =
      hash_entry(b_, struct spmt_pt_entry, hash_elem);
  return a->kpage < b->kpage;
}