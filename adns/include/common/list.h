
#ifndef _LIST_H_
#define _LIST_H_

/* Basic type for the double-link list.  */
struct list_head
{
  struct list_head *next;
  struct list_head *prev;
};

/* Define a variable with the head and tail of the list.  */
#define ADNS_LIST_HEAD(name) \
  struct list_head name = { &(name), &(name) }

/* Initialize a new list head.  */
#define INIT_LIST_HEAD(ptr) \
  (ptr)->next = (ptr)->prev = (ptr)

#define LIST_HEAD_INIT(name) { .prev = &(name), .next = &(name) }

/* Add new element at the head of the list.  */
static inline void
list_add (struct list_head *newp, struct list_head *head)
{
  head->next->prev = newp;
  newp->next = head->next;
  newp->prev = head;
  head->next = newp;
}


/* Add new element at the tail of the list.  */
static inline void
list_add_tail (struct list_head *newp, struct list_head *head)
{
  head->prev->next = newp;
  newp->next = head;
  newp->prev = head->prev;
  head->prev = newp;
}


/* Remove element from list.  */
static inline void
__list_del (struct list_head *prev, struct list_head *next)
{
  next->prev = prev;
  prev->next = next;
}

/* Remove element from list.  */
static inline void
list_del (struct list_head *elem)
{
  __list_del (elem->prev, elem->next);
}

/* Remove element from list, initializing the element's list pointers. */
static inline void
list_del_init (struct list_head *elem)
{
	list_del(elem);
	INIT_LIST_HEAD(elem);
}

/* delete from list, add to another list as head */
static inline void
list_move (struct list_head *elem, struct list_head *head)
{
  __list_del(elem->prev, elem->next);
  list_add (elem, head);
}

/* replace an old entry.
 */
static inline void
list_replace(struct list_head *old, struct list_head *_new)
{
	_new->next = old->next;
	_new->prev = old->prev;
	_new->prev->next = _new;
	_new->next->prev = _new;
}

/* Join two lists.  */
static inline void
list_splice (struct list_head *add, struct list_head *head)
{
  /* Do nothing if the list which gets added is empty.  */
  if (add != add->next)
    {
      add->next->prev = head;
      add->prev->next = head->next;
      head->next->prev = add->prev;
      head->next = add->next;
    }
}

/* Get typed element from list at a given position.  */
#define list_entry(ptr, type, member) \
  ((type *) ((char *) (ptr) - (unsigned long) (&((type *) 0)->member)))


/* Get first entry from a list. */
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)


/* Iterate forward over the elements of the list.  */
#define list_for_each(pos, head) \
  for (pos = (head)->next; pos != (head); pos = pos->next)


/* Iterate forward over the elements of the list.  */
#define list_for_each_prev(pos, head) \
  for (pos = (head)->prev; pos != (head); pos = pos->prev)


/* Iterate backwards over the elements list.  The list elements can be
   removed from the list while doing this.  */
#define list_for_each_prev_safe(pos, p, head) \
  for (pos = (head)->prev, p = pos->prev; \
       pos != (head); \
       pos = p, p = pos->prev)

#define list_for_each_entry_prev_safe(pos, p, head, member) \
  for (pos = list_entry((head)->prev, typeof(*pos), member), \
        p = list_entry(pos->member.prev, typeof(*pos), member);   \
        &pos->member != (head);          \
        pos = p, p = list_entry(pos->member.prev, typeof(*pos), member))

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_reverse(pos, head, member)			\
	for (pos = list_entry((head)->prev, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.prev, typeof(*pos), member))

#define list_for_each_entry_safe(pos, p, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		     p = list_entry(pos->member.next,typeof(*pos), member); \
	     &pos->member != (head);					\
	     pos = p, p = list_entry(pos->member.next, typeof(*pos), member))

static inline int list_empty(struct list_head *head)
{
	return head == head->next;
}

static inline void list_replace_init(struct list_head *old,
				     struct list_head *_new)
{
	struct list_head *head = old->next;
	list_del(old);
	list_add_tail(_new, head);
	INIT_LIST_HEAD(old);
}

#endif	/* _LIST_H_ */

