
/*
* Copyright (C)
* Filename: list_bulk.h
* Author:
* yisong <songyi.sy@alibaba-inc.com>
* Description: struct list_head_bulk is the core struct of this file
*              The usage of struct list_head_bulk is struct request_httpdns
*/

#ifndef __LIST_BULK_H__
#define __LIST_BULK_H__

#ifdef __cplusplus
extern "C" {
#endif

struct list_head_bulk
{
  struct list_head_bulk *next;
  struct list_head_bulk *prev;
  int num;
};

/* Get typed element from list at a given position.  */
#define list_entry_bulk(ptr, type, member) \
  ((type *) ((char *) (ptr) - (unsigned long) (&((type *) 0)->member) - sizeof(struct list_head_bulk) * ptr->num))

#define list_for_each_entry_bulk(pos, no, head, member)				\
	for (pos = list_entry_bulk((head)->next, typeof(*pos), member), no = (head)->next->num;	\
	     &pos->member[no] != (head);					\
	     pos = list_entry_bulk(pos->member[no].next, typeof(*pos), member), no = pos->member[no].next->num)

static inline int list_bulk_empty(struct list_head_bulk *head)
{
    return head == head->next;
}
    
/* Add new element at the tail of the list_bulk.  */
static inline void
list_bulk_add_tail (struct list_head_bulk *newp, int num, struct list_head_bulk *head)
{
  head->prev->next = newp;
  newp->next = head;
  newp->prev = head->prev;
  head->prev = newp;
  newp->num = num;
}

/* Remove element from list_bulk.  */
static inline void
__list_bulk_del (struct list_head_bulk *prev, struct list_head_bulk *next)
{
  next->prev = prev;
  prev->next = next;
}

/* Remove element from list_bulk.  */
static inline void
list_bulk_del (struct list_head_bulk *elem)
{
  __list_bulk_del (elem->prev, elem->next);
}

/* Get first entry from a list_bulk. */
#define list_bulk_first_entry(ptr, type, member) \
	list_entry_bulk((ptr)->next, type, member)

#ifdef __cplusplus
}
#endif
#endif
