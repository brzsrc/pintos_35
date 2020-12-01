#include "page.h"

struct hash spmt_pt;

static unsigned spmtpt_hash(const struct hash_elem *spmtpt_, void *aux UNUSED);
static bool spmtpt_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED);

<<<<<<< HEAD
void spmtpt_init(void) { 
    hash_init(&spmt_pt, spmtpt_hash, spmtpt_less, NULL); 
}

=======
>>>>>>> 918793ff4fd51ba6510b5036984a6517a92d7692
/* Returns a hash value for frame_node f. */
static unsigned spmtpt_hash(const struct hash_elem *spmtpt_, void *aux UNUSED) {
  const struct spmt_pt_entry *spmtpt =
      hash_entry(spmtpt_, struct spmt_pt_entry, hash_elem);
  return hash_bytes(&spmtpt->k, sizeof spmtpt->k);
}

/* Returns true if frame a precedes frame b. */
static bool spmtpt_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED) {
  const struct spmt_pt_entry *a =
      hash_entry(a_, struct spmt_pt_entry, hash_elem);
  const struct spmt_pt_entry *b =
      hash_entry(b_, struct spmt_pt_entry, hash_elem);
  return a->k.tid < b->k.tid;
}

void spmtpt_init() { hash_init(&spmt_pt, spmtpt_hash, spmtpt_less, NULL); }