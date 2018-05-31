#include "userprog/syscall.h"
#include "devices/input.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "userprog/exception.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

/* prototypes for syscalls */
static void sys_halt (void);
static void sys_exit (int status);
static tid_t sys_exec (const char *cmd_line);
static int sys_wait (tid_t pid);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);

/* lookup file descriptor list */
struct fd * lookup_fd(int fd);

/* checks if given address is in user memory */
bool check_uaddr (const void *uaddr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Calls the appropriate system call for the system call number */
static void
syscall_handler (struct intr_frame *f) 
{
  ASSERT(f != NULL);
  ASSERT(f->esp != NULL);

  if (check_uaddr(f->esp))
  {
    switch (*(uint32_t *)(f->esp))
    {
      case SYS_HALT:
        sys_halt();
        NOT_REACHED();
        break;
      case SYS_EXIT:
        if (check_uaddr((uint32_t *)(f->esp)+1))
          sys_exit(*(((int32_t *) (f->esp))+1));
        else
          sys_exit(-1);
        break;
      case SYS_EXEC:
        if (check_uaddr((uint32_t *)(f->esp)+1))
          f->eax = sys_exec( (char *) *(((uint32_t *) (f->esp))+1));
        else
          sys_exit(-1);
        break;
      case SYS_WAIT:
        if (check_uaddr((uint32_t *)(f->esp)+1))
          f->eax = sys_wait(*(((uint32_t *) (f->esp))+1));
        else
          sys_exit(-1);
        break;
      case SYS_CREATE:
        if (check_uaddr((uint32_t *)(f->esp)+1) && check_uaddr((uint32_t *)(f->esp)+2))
          f->eax = sys_create( (char *) *(((uint32_t *) (f->esp))+1), *(((uint32_t *) (f->esp))+2));
        else
          sys_exit(-1);
        break;
      case SYS_REMOVE:
        if (check_uaddr((uint32_t *)(f->esp)+1))
          f->eax = sys_remove( (char *) *(((uint32_t *) (f->esp))+1));
        else
          sys_exit(-1);
        break;
      case SYS_OPEN:
        if (check_uaddr((uint32_t *)(f->esp)+1))
          f->eax = sys_open( (char *) *(((uint32_t *) (f->esp))+1));
        else
          sys_exit(-1);
        break;
      case SYS_FILESIZE:
        if (check_uaddr((uint32_t *)(f->esp)+1))
          {
            f->eax = sys_filesize(*(((uint32_t *) (f->esp))+1));
          }
        else
          sys_exit(-1);
        break;
      case SYS_READ:
        if (check_uaddr((uint32_t *)(f->esp)+1)
	        && check_uaddr((uint32_t *)(f->esp)+2)
	        && check_uaddr((uint32_t *)(f->esp)+3))
          {
            f->eax = sys_read(*(((uint32_t *) (f->esp))+1), (void *) *(((uint32_t *) (f->esp))+2), *(((uint32_t *) (f->esp))+3));
          }
        else
          sys_exit(-1);
        break;
      case SYS_WRITE:
        if (check_uaddr((uint32_t *)(f->esp) + 1) 
            && check_uaddr((uint32_t *)(f->esp) + 2)
            && check_uaddr((uint32_t *)(f->esp) + 3))
        {
          f->eax = sys_write(*(((uint32_t *) (f->esp))+1), (void *) *(((uint32_t *) (f->esp))+2), *(((uint32_t *) (f->esp))+3));
        }
        else
          sys_exit(-1);
        break;
      case SYS_SEEK:
        if (check_uaddr((uint32_t *)(f->esp)+1) && check_uaddr((uint32_t *)(f->esp)+2))
          sys_seek(*(((uint32_t *) (f->esp))+1), *(((uint32_t *) (f->esp))+2));
        else
          sys_exit(-1);
        break;
      case SYS_TELL:
        if (check_uaddr((uint32_t *)(f->esp)+1))
          {
            f->eax = sys_tell(*(((uint32_t *) (f->esp))+1));
          }
        else
          sys_exit(-1);
        break;
      case SYS_CLOSE:
        if (check_uaddr((uint32_t *)(f->esp)+1))
          sys_close(*(((uint32_t *) (f->esp))+1));
        else
          sys_exit(-1);
        break;
      default:
        sys_exit(-1);
        break;
    }
  }
  else
  {
    sys_exit(-1);
  }
}

/* Terminates Pintos */
static void
sys_halt(void)
{
  power_off ();
}

/* Terminates the current user program, returning status to the kernel. */
static void
sys_exit (int status)
{
  struct thread *curr = thread_current ();
  struct child *entry;


  if (curr->parent != NULL)
    {
      lock_acquire(&curr->parent->family_lock);
      ASSERT(!list_empty(&curr->parent->children_list));

      if ((entry = lookup_child(curr->tid, curr->parent)) != NULL)
        {
          while(!entry->waited)
            cond_wait(&curr->parent->family_cond, &curr->parent->family_lock);

          entry->status = status;
          entry->exited = true;
          cond_broadcast(&curr->parent->family_cond, &curr->parent->family_lock);
        }
      lock_release(&curr->parent->family_lock);
    }

  char *ptr = strchr(curr->name, ' ');
  if (ptr == NULL)
    ptr = curr->name + strlen(curr->name);
  uint32_t nlen = (uint32_t) ptr - (uint32_t) (curr->name);
  char *temp = calloc(nlen+1, 1);
  memcpy(temp, curr->name, nlen);

  printf("%s: exit(%d)\n", temp, status);

  free(temp);
  thread_exit();
}

/* Runs the executable whose name is given in cmd_line, passing any given arguments,
   and returns the new process's program id (pid).*/
static tid_t
sys_exec (const char *cmdline)
{
  if (!check_uaddr(cmdline))
    sys_exit(-1);

  tid_t cpid = process_execute(cmdline);

  if (cpid == TID_ERROR)
    cpid = -1;
  else
    {
      struct thread * curr = thread_current();

      lock_acquire(&curr->family_lock);
        {
          struct child *entry;

          entry = lookup_child(cpid, curr);

          /* The corresponding child should be in the list by now */
          ASSERT(entry != NULL);

            while (entry->status == LOADING)
              cond_wait(&curr->family_cond, &curr->family_lock);

          if (entry->status == FAILED)
            {
              list_remove(&entry->elem);
              free(entry);   
              cpid = -1;
            }
        }
      lock_release(&curr->family_lock);
    }

  return cpid;
}

/* Waits for a child process pid and retrieves the child's exit status. */
static int
sys_wait (tid_t pid)
{
  return process_wait(pid);
}

/* Creates a new file called file initially initial_size bytes in size.
  Returns true if successful, false otherwise. */
static bool
sys_create (const char *file, unsigned initial_size)
{
  if(!check_uaddr(file))
    sys_exit(-1);

  bool ret = false;

  lock_acquire(&filesys_lock);
    ret = filesys_create(file, initial_size);
  lock_release(&filesys_lock);

  return ret;
}

/* Deletes the file called file. Returns true if successful, false otherwise. */
static bool
sys_remove (const char *file)
{
  if(!check_uaddr(file))
    sys_exit(-1);

  bool ret = false;

  lock_acquire(&filesys_lock);
    ret = filesys_remove(file);
  lock_release(&filesys_lock);

  return ret;
}

/* Opens the file called file. Returns a nonnegative integer handle called a "file descriptor" (fd),
   or -1 if the file could not be opened. */
static int
sys_open (const char *file)
{
  if(!check_uaddr(file))
    sys_exit(-1);

  int fd = -1;
  struct file *opened;

  /* open file */
  lock_acquire(&filesys_lock);
    opened = filesys_open(file);
  lock_release(&filesys_lock);

  /* if file is opened, add to open file list */
  if (opened != NULL)
    {
      struct thread *curr = thread_current();
      struct fd *entry = calloc(sizeof(struct fd), 1);

      entry->file = opened;
      entry->fd = list_size(&curr->open_fds)+3;
      entry->thread = curr;
      list_push_front(&curr->open_fds, &entry->elem);

      fd = entry->fd;   
    }

  return fd;
}

/* Returns the size, in bytes, of the file open as fd. */
static int
sys_filesize (int fd)
{
  int ret = -1;
  struct fd *entry;

  if ((entry = lookup_fd(fd)) != NULL)
    {
      lock_acquire(&filesys_lock);
        ret = file_length(entry->file);
      lock_release(&filesys_lock);
    }

  return ret;
}

/* Reads size bytes from the file open as fd into buffer.
   Returns the number of bytes actually read (0 at end of file),
   or -1 if the file could not be read (due to a condition other than end of file). */
static int
sys_read (int fd, void *buffer, unsigned size)
{
  if (!check_uaddr(buffer))
    sys_exit(-1);

  int ret = -1;

  if (fd == 0)
    {
      /* read from stdin */
      int index;
      char *temp = (char *)buffer;
      for (index=0; (unsigned) index < size; index++)
        temp[index] = (char) input_getc();
      ret = index;
    }
  else
    {
      /* read from designated fd */
      struct fd *entry;

      lock_acquire(&filesys_lock);
      if ((entry = lookup_fd(fd)) != NULL)
        {
          off_t file_size = file_length(entry->file);
          if ((unsigned)file_size > size)
            ret = file_read(entry->file, buffer, size);
          else
            ret = file_read(entry->file, buffer, file_size);
        }
      lock_release(&filesys_lock);
    }
  return ret;
}

/* Writes size bytes from buffer to the open file fd.
   Returns the number of bytes actually written,
   which may be less than size if some bytes could not be written.*/
static int
sys_write (int fd, void *buffer, unsigned size)
{
  if (!check_uaddr(buffer))
    sys_exit(-1);

  int ret = -1;

  if (fd == 1)
    {
      /* write to stdout */
      unsigned temp = size;
      ret = 0;

      while (temp > 512)
        {
          putbuf(buffer+ret, 512);
          ret += 512;
          temp -= 512;
        }
      putbuf(buffer+ret, temp);
      ret += temp;
    }
  else
    {
      /* write to designated file */
      struct fd *entry;

      lock_acquire(&filesys_lock);
        {
          if ((entry = lookup_fd(fd)) != NULL)
            {
              off_t file_size = file_length(entry->file);

              if ((unsigned)file_size > size)
                ret = file_write(entry->file, buffer, size);
              else
                ret = file_write(entry->file, buffer, file_size);
            }
        }              
      lock_release(&filesys_lock);
    }

  return ret;
}

/* Changes the next byte to be read or written in open file fd to position,
   expressed in bytes from the beginning of the file.*/
static void
sys_seek (int fd, unsigned position)
{
  struct fd *entry;

  if ((entry = lookup_fd(fd)) != NULL)
    file_seek(entry->file, position);
}

/* Returns the position of the next byte to be read or written in open file fd,
   expressed in bytes from the beginning of the file. */
static unsigned
sys_tell (int fd)
{
  unsigned ret = 0;
  struct fd *entry;

  if ((entry = lookup_fd(fd)) != NULL)
    ret = file_tell(entry->file);

  return ret;
}

/* Closes file descriptor fd. */
static void
sys_close (int fd)
{
  struct fd *entry;

  if ((entry = lookup_fd(fd)) != NULL)
    {
      lock_acquire(&filesys_lock);
        file_close(entry->file);
      lock_release(&filesys_lock);

      list_remove(&entry->elem);
      free(entry);
    }
}

/* Checks if uaddr points to a valid user address */
bool
check_uaddr (const void *uaddr)
{
  return (uaddr != NULL)
         && (is_user_vaddr(uaddr)) 
         && ((pagedir_get_page(thread_current()->pagedir, uaddr) != NULL));
}

/* Finds the corresponding fd pointer associated with an integer fd */ 
struct fd*
lookup_fd(int fd)
{
  struct fd *ret = NULL;
  struct thread *curr = thread_current();

  if (!list_empty(&curr->open_fds))
    {
      struct list_elem *e;
      for (e = list_begin(&curr->open_fds);
           e != list_end(&curr->open_fds);
           e = list_next(e))
        {
          struct fd *entry = list_entry(e, struct fd, elem);
          if (entry->fd == fd)
            ret = entry;
        }
    }

  return ret;
}
