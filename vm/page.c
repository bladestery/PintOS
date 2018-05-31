#include "page.h"
#include <stdint.h>
#include <stdbool.h>
#include "threads/thread.h"
#include "threads/malloc.h"

void destructor(struct hash_elem* hash_elem, void *aux UNUSED);

struct page *create_page(struct file *file, off_t offset, uint32_t read_bytes, uint32_t zero_bytes, bool writable, uint32_t *vir_addr)
{
    struct page *kpage;
    if ((kpage = (struct page *) malloc(sizeof(struct page))) == NULL)
        return kpage;
    else
    {
        kpage->vir_addr = vir_addr;
        kpage->page_loc = not_loaded;
        kpage->page_t = DEF;
        kpage->file = file;
        kpage->offset = offset;
        kpage->read_bytes = read_bytes;
        kpage->zero_bytes = zero_bytes;
        kpage->writable = writable;
        
        return kpage;
    }
}

struct page *get_page(void *vir_addr)
{
    struct thread *curr = thread_current();
    struct hash_elem *result;
    struct page entry;
    
    entry.vir_addr = vir_addr;
    result = hash_find(&curr->sup_table, &entry.hash_elem);
    return hash_entry (result, struct page, hash_elem);
}

void add_page(struct page *kpage)
{
    struct thread *curr = thread_current();
    lock_acquire(&curr->sup_lock);
    hash_insert(&curr->sup_table, &kpage->hash_elem);
    lock_release(&curr->sup_lock);
}

void destructor(struct hash_elem* hash_elem, void *aux UNUSED)
{
    struct page *p = hash_entry(hash_elem, struct page, hash_elem);
    free(p);
}

void release_pages(struct hash* hash)
{
    struct thread *curr = thread_current();
    lock_acquire(&curr->sup_lock);
    hash_destroy(hash, &destructor); /* need to free each hash elem */
    lock_release(&curr->sup_lock);
}

unsigned page_hash(struct hash_elem *elem, void *aux)
{
    struct page *temp = (struct page *) hash_entry(elem, struct page, hash_elem);
    return hash_bytes(&temp->vir_addr, sizeof(temp->vir_addr));
}

bool page_less_func(struct hash_elem *elem_1, struct hash_elem *elem_2, void *aux)
{
    struct page *page_1 = (struct page *) hash_entry(elem_1, struct page, hash_elem);
    struct page *page_2 = (struct page *) hash_entry(elem_2, struct page, hash_elem);
    
    return (page_2 - page_1 > 0);
}
