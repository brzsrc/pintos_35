#include "page.h"

#include "threads/malloc.h"

static unsigned spmtpt_hash(const struct hash_elem *spmtpt_, void *aux UNUSED);
static bool spmtpt_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED);

void spmtpt_init(struct hash *spmt_pt) {
  hash_init(spmt_pt, spmtpt_hash, spmtpt_less, NULL);
}

// Malloc. Since we assert non null, returned is always a valid pointer
struct spmt_pt_entry *spmtpt_entry_init(void *upage, void *kpage,
                                        struct load_page_detail load_details) {
  struct spmt_pt_entry *entry =
      (struct spmt_pt_entry *)malloc(sizeof(struct spmt_pt_entry));
  // Raw check if malloc is successful
  ASSERT(entry != NULL);
  entry->upage = upage;
  entry->kpage = kpage;
  entry->load_details = load_details;
  return entry;
}

/* Use entry->upage as the key for hash */
static unsigned spmtpt_hash(const struct hash_elem *spmtpt_, void *aux UNUSED) {
  const struct spmt_pt_entry *spmtpt =
      hash_entry(spmtpt_, struct spmt_pt_entry, hash_elem);
  return hash_bytes(&spmtpt->upage, sizeof spmtpt->upage);
}

/* Returns true if spmt_pt_entry a precedes spmt_pt_entry b. */
static bool spmtpt_less(const struct hash_elem *a_, const struct hash_elem *b_,
                        void *aux UNUSED) {
  const struct spmt_pt_entry *a =
      hash_entry(a_, struct spmt_pt_entry, hash_elem);
  const struct spmt_pt_entry *b =
      hash_entry(b_, struct spmt_pt_entry, hash_elem);
  return a->upage < b->upage;
}

struct hash_elem *spmtpt_insert(struct hash *spmtpt,
                                struct spmt_pt_entry *entry) {
  struct hash_elem *e;
  e = hash_insert(spmtpt, &entry->hash_elem);
  return e;
}

struct spmt_pt_entry *spmtpt_find(struct hash *spmtpt, uint8_t *upage) {
  // dummy struct used as the key. See sepc page 78-79
  struct spmt_pt_entry key;
  struct hash_elem *e;

  key.upage = upage;
  e = hash_find(spmtpt, &key.hash_elem);
  return e != NULL ? hash_entry(e, struct spmt_pt_entry, hash_elem) : NULL;
}

void spmtpt_free(struct hash *spmt_pt) {
  // TODO free every entry and free the struct hash
  // hash_destroy(spmt_pt, free_spmtpt_entry);
  return;
}