#include "devices/disk.h"
#include <stdlib.h>
#include "vm/frame.h"

#ifndef SWAP_H
#define SWAP_H

struct bitmap *swap_bitmap;
struct disk *disk;
disk_sector_t swap_disk_size;
struct lock swap_lock;

void init_swap(void);

struct frame *swap_out_frame(struct frame *frame);

void swap_in_frame(struct frame *frame);

void free_sect(size_t index);

void release_swaps(void);

#endif
