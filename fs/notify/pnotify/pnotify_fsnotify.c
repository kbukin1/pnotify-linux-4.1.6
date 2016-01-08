/*
 * pnotify_fsnotify.c
 *
 * Authors:
 *	John McCutchan	<ttb@tentacle.dhs.org>
 *	Robert Love	<rml@novell.com>
 *
 * Copyright (C) 2005 John McCutchan
 * Copyright 2006 Hewlett-Packard Development Company, L.P.
 *
 * Copyright (C) 2009 Eric Paris <Red Hat Inc>
 * inotify was largely rewriten to make use of the fsnotify infrastructure
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 *  This is pnotify_fsnotify.c, which is a copy and modification of
 *  inotify_fsnotify.c
 *
 *  --John F. Hubbard <jhubbard@nvidia.com> 01 Dec 2011
 *
 */

#include <linux/dcache.h> /* d_unlinked */
#include <linux/fs.h> /* struct inode */
#include <linux/fsnotify_backend.h>
#include <linux/inotify.h>
#include <linux/path.h> /* struct path */
#include <linux/slab.h> /* kmem_* */
#include <linux/types.h>
#include <linux/sched.h>

#include "pnotify.h"

/*
 * Check if 2 events contain the same information.  We do not compare private data
 * but at this moment that isn't a problem for any know fsnotify listeners.
 */
static bool pnotify_event_compare(struct fsnotify_event *old_fsn, struct fsnotify_event *new_fsn)
{
  struct pnotify_event_info *old, *new;

  if (old_fsn->mask & FS_IN_IGNORED)
    return false;
  old = PNOTIFY_E(old_fsn);
  new = PNOTIFY_E(new_fsn);
  if ((old_fsn->mask == new_fsn->mask) &&
      (old_fsn->inode == new_fsn->inode) &&
      (old->name_len == new->name_len) &&
      (!old->name_len || !strcmp(old->name, new->name)))
    return true;
  return false;
}

#if 0
static struct fsnotify_event *pnotify_merge(struct list_head *list,
					    struct fsnotify_event *event)
{
	struct fsnotify_event_holder *last_holder;
	struct fsnotify_event *last_event;
#if 0
	/* and the list better be locked by something too */
	spin_lock(&event->lock);

	last_holder = list_entry(list->prev, struct fsnotify_event_holder, event_list);
	last_event = last_holder->event;
	if (pnotify_event_compare(last_event, event))
		fsnotify_get_event(last_event);
	else
		last_event = NULL;

	spin_unlock(&event->lock);
#endif
	return last_event;
}
#endif

static int pnotify_merge(struct list_head *list,
			                   struct fsnotify_event *event)
{
	struct fsnotify_event *last_event;

	last_event = list_entry(list->prev, struct fsnotify_event, list);
	return pnotify_event_compare(last_event, event);
}


/**
 * @path_arg: path to report
 * @buff: buffer to return value in
 * @buff_size: buffer length
 * @name: file name
 *
 * Returns a pointer into the buffer or an error code if the path was
 * too long. Note: Callers should use the returned pointer, not the passed
 * in buffer, to use the name! The implementation often starts at an offset
 * into the buffer, and may leave 0 bytes at the start.
 *
 * "buff_size" should be positive.
 */
static char* pnotify_fullpath_from_path(char* buff,
                                        int buff_size,
                         				        struct path *path_arg,
                                        const unsigned char *name)
{
  int length;
	char* ret = buff + buff_size - 1;

  if (!buff || buff_size <= 0)
    return ERR_PTR(-EINVAL);

	pnotify_debug(PNOTIFY_DEBUG_LEVEL_DEBUG_EVENTS,
		      "%s: path: 0x%p (denty: %p), name: %s\n",
		      __func__, path_arg, path_arg ? path_arg->dentry : NULL,
		      (char*)(name ? name : (const unsigned char*)"NULL"));

  *ret = '\0';

  if (name) {
    length = strlen(name);
    if (unlikely(length >= buff_size))
      return ERR_PTR(-ENOMEM);

    memcpy(buff + buff_size - length - 1, name, length);
    ret -= length;
  }

  if (path_arg && current->fs /* KB_TODO: need to understand why current->fs is sometimes zero */ ) {
    path_get(path_arg);
		ret = d_path(path_arg, buff, ret - buff);
    path_put(path_arg);

		if (IS_ERR(ret)) {
			pnotify_debug(PNOTIFY_DEBUG_LEVEL_DEBUG_EVENTS,
          "%s: dpath failed: %p\n", __func__, ret);
		}
	}

  return ret;
}

int pnotify_handle_event(struct fsnotify_group *group,
			                   struct inode *inode,
                         struct fsnotify_mark *inode_mark,
                         struct fsnotify_mark *vfsmount_mark,
                         u32 mask, void *data, int data_type,
                         const unsigned char *file_name, u32 cookie,
                         pid_t tgid, pid_t pid, pid_t ppid, 
                         struct path *path_for_inode_events /* KB_TODO: need to revisit */, unsigned long status)
{
	struct pnotify_inode_mark *i_mark;
	struct pnotify_event_info *event;
	struct fsnotify_event *fsn_event;
	int ret;
  char *buffer = 0;
	int len = 0;
  char* page = 0;
	int alloc_len = sizeof(struct pnotify_event_info);

	BUG_ON(vfsmount_mark);

	if ((inode_mark->mask & FS_EXCL_UNLINK) &&
	    (data_type == FSNOTIFY_EVENT_PATH)) {
		struct path *path = data;

		if (d_unlinked(path->dentry))
			return 0;
	}

	pr_debug("%s: group=%p inode=%p mask=%x\n", __func__, 
      group, inode, mask);
	pnotify_debug(PNOTIFY_DEBUG_LEVEL_VERBOSE, 
      "%s: group=%p data_type=%d inode=%p mask=%x path_for_inode_events=%p data=%p file_name=%s\n", 
      __func__, group, data_type, inode, mask, path_for_inode_events, data,
      (file_name ? file_name : (unsigned char*) "NULL")); // why file_name is unsigned?


  switch (data_type) {
    case FSNOTIFY_EVENT_PATH: {
        struct path *path = data;

        if (pid) {
          page = (char *) __get_free_page(GFP_KERNEL);
          if (unlikely(!page))
            return -ENOMEM;

          buffer = pnotify_fullpath_from_path(page, PAGE_SIZE, path, file_name);

          if (IS_ERR(buffer)) {
            pnotify_debug(PNOTIFY_DEBUG_LEVEL_DEBUG_EVENTS,
                "%s: mask 0x%0x data_type=%d, "
                "FULL_PATH_FROM_PATH(1) FAILED, "
                "pid %u: %p\n", __func__, mask,
                data_type, pid, buffer);
          }
          else {
            len = PAGE_SIZE - (buffer - page) - 1;
          }
        }
       }
       break;
    case FSNOTIFY_EVENT_INODE: {
      struct inode *inode = data;
      if (pid) {
        if (inode) {

          page = (char *) __get_free_page(GFP_KERNEL);
          if (unlikely(!page))
            return -ENOMEM;

          buffer = pnotify_fullpath_from_path(page, PAGE_SIZE, path_for_inode_events, file_name);

          if (IS_ERR(buffer)) {
            pnotify_debug(PNOTIFY_DEBUG_LEVEL_DEBUG_EVENTS,
                "%s: mask 0x%0x data_type=%d, "
                "FULL_PATH_FROM_PATH(1) FAILED, "
                "pid %u: %p\n", __func__, mask,
                data_type, pid, buffer);
          }
          else {
            len = PAGE_SIZE - (buffer - page) - 1;
          }
          
        }
       }
      }
      break;
    case FSNOTIFY_EVENT_NONE:
      buffer = (char*) file_name;
      len = file_name ? strlen(file_name) : 0;
      break;
    default:
      BUG();
  }

  alloc_len += len + 1;

	i_mark = container_of(inode_mark, struct pnotify_inode_mark,
			      fsn_mark);

	event = kmalloc(alloc_len, GFP_KERNEL);
	if (unlikely(!event))
		return -ENOMEM;

	fsn_event = &event->fse;
	fsnotify_init_event(fsn_event, inode, mask);
	event->wd = i_mark->wd;
	event->sync_cookie = cookie;

	event->tgid = tgid;
	event->pid = pid;
	event->ppid = ppid;
	event->status = status;
	event->jiffies = get_jiffies_64();

	event->name_len = len;
  if (len) {
    memcpy(event->name, buffer, len);
  }
  *(event->name + len) = '\0';

  //pnotify_debug(PNOTIFY_DEBUG_LEVEL_DEBUG_EVENTS,
  //    "%s: found path: buffer=[%s], len=%d\n", 
  //    __func__, buffer ? buffer : "NULL", len);

  switch (data_type) {
    case FSNOTIFY_EVENT_PATH: {
        struct path *path = data;
        if (path && path->dentry && path->dentry->d_inode) {
          event->inode_num = path->dentry->d_inode->i_ino;
        }
       }
       break;
    case FSNOTIFY_EVENT_INODE: {
      struct inode *inode = data;
      if (pid) {
        if (inode) {
          event->inode_num = inode->i_ino;

        }
       }
      }
      break;
    case FSNOTIFY_EVENT_NONE:
      event->inode_num = 0;
      break;
    default:
      BUG();
  }

	ret = fsnotify_add_event(group, fsn_event, pnotify_merge);
	if (ret) {
		/* Our event wasn't used in the end. Free it. */
		fsnotify_destroy_event(group, fsn_event);
	}

	if (inode_mark->mask & IN_ONESHOT)
		fsnotify_destroy_mark(inode_mark, group);

  if (page)
    free_page((unsigned long) page);

	return 0;

}

static void pnotify_freeing_mark(struct fsnotify_mark *fsn_mark, struct fsnotify_group *group)
{
	pnotify_ignored_and_remove_idr(fsn_mark, group);
}

/*
 * This is NEVER supposed to be called.  Inotify marks should either have been
 * removed from the idr when the watch was removed or in the
 * fsnotify_destroy_mark_by_group() call when the pnotify instance was being
 * torn down.  This is only called if the idr is about to be freed but there
 * are still marks in it.
 */
static int idr_callback(int id, void *p, void *data)
{
	struct fsnotify_mark *fsn_mark;
	struct pnotify_inode_mark *t_mark;
	static bool warned = false;

	if (warned)
		return 0;

	warned = true;
	fsn_mark = p;
	t_mark = container_of(fsn_mark, struct pnotify_inode_mark, fsn_mark);

	WARN(1, "pnotify closing but id=%d for fsn_mark=%p in group=%p still in "
		"idr.  Probably leaking memory\n", id, p, data);

	/*
	 * I'm taking the liberty of assuming that the mark in question is a
	 * valid address and I'm dereferencing it.  This might help to figure
	 * out why we got here and the panic is no worse than the original
	 * BUG() that was here.
	 */
	if (fsn_mark)
		printk(KERN_WARNING "fsn_mark->group=%p task=%p wd=%d\n",
			fsn_mark->group, fsn_mark->task, t_mark->wd);
	return 0;
}

static void pnotify_free_group_priv(struct fsnotify_group *group)
{
  pnotify_free_wd_pid_list(group);

	/* ideally the idr is empty and we won't hit the BUG in the callback */
	idr_for_each(&group->pnotify_data.idr, idr_callback, group);
	idr_destroy(&group->pnotify_data.idr);
	if (group->pnotify_data.user) {
		atomic_dec(&group->pnotify_data.user->pnotify_devs);
		free_uid(group->pnotify_data.user);
	}
}

void pnotify_free_event(struct fsnotify_event *fsn_event)
{
  kfree(PNOTIFY_E(fsn_event));
}

const struct fsnotify_ops pnotify_fsnotify_ops = {
	.handle_event = pnotify_handle_event, 
	.free_group_priv = pnotify_free_group_priv,
	.free_event = pnotify_free_event,
	.freeing_mark = pnotify_freeing_mark, 
};

