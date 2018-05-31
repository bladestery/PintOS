#include "vm/swap.h"
#include "vm/page.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "userprog/syscall.h"
#include <stdlib.h>
#include <bitmap.h>
#include <hash.h>
#include <string.h>
#include <stdio.h>


/* add error checking code */

void init_swap(void)
{
    lock_init(&swap_lock);
    
    disk = disk_get (1, 1);
    
    if (disk == NULL)
        ASSERT(0);
    
    swap_disk_size = disk_size(disk);
    swap_bitmap = bitmap_create(swap_disk_size);
    
    return;
}

struct frame *swap_out_frame(struct frame *frame)
{
    lock_acquire(&swap_lock);
    size_t index = bitmap_scan_and_flip(swap_bitmap, 0, 4, false);
    
    int i;
    for (i = 0; i < 4; i++)
        disk_write(disk, index + i, frame->phys_addr + DISK_SECTOR_SIZE * i);
    lock_release(&swap_lock);
    frame->page->swap_index = index;
    frame->page->page_loc = swap_disk;
    frame->page->page_t = SWAP;
    
    memset(frame + sizeof(uint32_t *), 0, PGSIZE - sizeof(uint32_t *));
    
    return frame;
}

void swap_in_frame(struct frame *frame)
{
    struct evict_info *entry = (struct evict_info *) malloc(sizeof(struct evict_info));
    entry->phys_addr = frame->phys_addr;
    lock_acquire(&evict.lock);
    list_push_back(&evict.pool, &entry->elem);
    lock_release(&evict.lock);
    
    lock_acquire(&swap_lock);
    bitmap_set_multiple (swap_bitmap, frame->page->swap_index, 4, false);
    
    int i;
    for (i = 0; i < 4; i++)
        disk_read(disk, frame->page->swap_index + i, frame->phys_addr + DISK_SECTOR_SIZE * i);
    lock_release(&swap_lock);
    frame->page->swap_index = 0;
    frame->page->page_loc = in_memory;
    frame->page->page_t = FILE;
    return;
}

void free_sect(size_t index)
{
    lock_acquire(&swap_lock);
    bitmap_set_multiple(swap_bitmap, index, 4, false);
    lock_release(&swap_lock);
    return;
}

void release_swaps(void)
{
    struct thread *t = thread_current();
    
    struct hash_iterator i;
    
    hash_first(&i, &t->sup_table);
    while(hash_next(&i))
    {
        struct page *f = hash_entry(hash_cur(&i), struct page, hash_elem);
        if (f->page_loc == swap_disk)
            free_sect(f->swap_index);
    }
}
