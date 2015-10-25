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
static bool pnotify_event_compare(struct fsnotify_event *old, struct fsnotify_event *new)
{
#if 0
	if ((old->mask == new->mask) &&
	    (old->to_tell == new->to_tell) &&
	    (old->data_type == new->data_type) &&
	    (old->name_len == new->name_len)) {
		switch (old->data_type) {
		case (FSNOTIFY_EVENT_INODE):
			/* remember, after old was put on the wait_q we aren't
			 * allowed to look at the inode any more, only thing
			 * left to check was if the file_name is the same */
			if (!old->name_len ||
			    !strcmp(old->file_name, new->file_name))
				return true;
			break;
		case (FSNOTIFY_EVENT_PATH):
			if ((old->path.mnt == new->path.mnt) &&
			    (old->path.dentry == new->path.dentry))
				return true;
			break;
		case (FSNOTIFY_EVENT_NONE):
			if (old->mask & FS_Q_OVERFLOW)
				return true;
			else if (old->mask & FS_IN_IGNORED)
				return false;
			return true;
		};
	}
#endif
	return false;
}

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

static int pnotify_handle_event(struct fsnotify_group *group,
			                   struct inode *inode,
                         struct fsnotify_mark *inode_mark,
                         struct fsnotify_mark *vfsmount_mark,
                         u32 mask, void *data, int data_type,
                         const unsigned char *file_name, u32 cookie,
                         pid_t tgid, pid_t pid, pid_t ppid, 
                         struct path *path, unsigned long status)
{
	struct pnotify_inode_mark *i_mark;
	struct pnotify_event_info *event;
	struct fsnotify_event *fsn_event;
	int ret;
	int len = 0;
	int alloc_len = sizeof(struct pnotify_event_info);

	BUG_ON(vfsmount_mark);

	if ((inode_mark->mask & FS_EXCL_UNLINK) &&
	    (data_type == FSNOTIFY_EVENT_PATH)) {
		struct path *path = data;

		if (d_unlinked(path->dentry))
			return 0;
	}
	if (file_name) {
		len = strlen(file_name);
		alloc_len += len + 1;
	}

	pr_debug("%s: group=%p inode=%p mask=%x\n", __func__, 
      group, inode, mask);
	pnotify_debug(PNOTIFY_DEBUG_LEVEL_VERBOSE, 
      "%s: group=%p inode=%p mask=%x path=%p\n", __func__, 
      group, inode, mask, path);

	i_mark = container_of(inode_mark, struct pnotify_inode_mark,
			      fsn_mark);

	event = kmalloc(alloc_len, GFP_KERNEL);
	if (unlikely(!event))
		return -ENOMEM;

	fsn_event = &event->fse;
	fsnotify_init_event(fsn_event, inode, mask);
	event->wd = i_mark->wd;
	event->sync_cookie = cookie;
	event->name_len = len;

	event->tgid = tgid;
	event->pid = pid;
	event->ppid = ppid;
	event->status = status;
	event->jiffies = get_jiffies_64();
	event->inode_num = path ? path->dentry->d_inode->i_ino : 0;

	if (len)
		strcpy(event->name, file_name);

	ret = fsnotify_add_event(group, fsn_event, pnotify_merge);
	if (ret) {
		/* Our event wasn't used in the end. Free it. */
		fsnotify_destroy_event(group, fsn_event);
	}

	if (inode_mark->mask & IN_ONESHOT)
		fsnotify_destroy_mark(inode_mark, group);

	return 0;

}

static void pnotify_freeing_mark(struct fsnotify_mark *fsn_mark, struct fsnotify_group *group)
{
	pnotify_ignored_and_remove_idr(fsn_mark, group);
}

static bool pnotify_should_send_event(struct fsnotify_group *group, struct inode *inode,
				      struct fsnotify_mark *inode_mark,
				      struct fsnotify_mark *vfsmount_mark,
				      __u32 mask, void *data, int data_type)
{
	return true;
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
	struct pnotify_wd_pid_struct *pos, *tmp;
	struct list_head local_list;
	INIT_LIST_HEAD(&local_list);
#if 0
	/* ideally the idr is empty and we won't hit the BUG in the callback */
	idr_for_each(&group->pnotify_data.idr, idr_callback, group);
	idr_remove_all(&group->pnotify_data.idr);
	idr_destroy(&group->pnotify_data.idr);
	atomic_dec(&group->pnotify_data.user->pnotify_devs);
	free_uid(group->pnotify_data.user);

	spin_lock(&group->pnotify_data.wd_pid_lock);

	list_for_each_entry_safe(pos, tmp,
				 &group->pnotify_data.wd_pid_list,
				 pnotify_wd_pid_list_item) {

		pnotify_debug(PNOTIFY_DEBUG_LEVEL_VERBOSE,
			      "%s: deleting entry group: %p, wd=%d, pid=%u\n",
			      __func__, group, pos->wd, pos->pid);

		list_del_init(&pos->pnotify_wd_pid_list_item);
		list_add_tail(&pos->pnotify_wd_pid_list_item, &local_list);
	}
	spin_unlock(&group->pnotify_data.wd_pid_lock);

	/* Now that the list items are on a local list, they can be safely
	   deleted without holding any locks */
	list_for_each_entry_safe(pos, tmp, &local_list,
				 pnotify_wd_pid_list_item) {
		list_del(&pos->pnotify_wd_pid_list_item);
		kmem_cache_free(pnotify_wd_pid_cachep, pos);
	}
#endif
}

void pnotify_free_event_priv(struct fsnotify_event_private_data *fsn_event_priv)
{
	struct pnotify_event_private_data *event_priv;

#if 0
	event_priv = container_of(fsn_event_priv, struct pnotify_event_private_data,
				  fsnotify_event_priv_data);

	kmem_cache_free(pnotify_event_priv_cachep, event_priv);
#endif
}

const struct fsnotify_ops pnotify_fsnotify_ops = {
	.handle_event = pnotify_handle_event,
	// .should_send_event = pnotify_should_send_event,
	.free_group_priv = pnotify_free_group_priv,
	// .free_event_priv = pnotify_free_event_priv,
	.free_event = pnotify_free_event_priv,
	.freeing_mark = pnotify_freeing_mark,
};
