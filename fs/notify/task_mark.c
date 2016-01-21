/*
 *  Copyright (C) 2008 Red Hat, Inc., Eric Paris <eparis@redhat.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; see the file COPYING.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  This is task_mark.c, which is a copy and modification of inode_mark.c
 *  --John F. Hubbard <jhubbard@nvidia.com> 01 Dec 2011
 *
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

#include <linux/atomic.h>

#include <linux/fsnotify_backend.h>
#include "fsnotify.h"

/*
 * Recalculate the mask of events relevant to a given task locked.
 */
void fsnotify_recalc_task_mask(struct task_struct *task)
{
	spin_lock(&task->alloc_lock);
	task->pnotify_mask = fsnotify_recalc_mask(&task->pnotify_marks);
	spin_unlock(&task->alloc_lock);

    // XXX-4.1.6
	// __fsnotify_update_child_dentry_flags(inode);
}

/*
 * Recalculate the task->pnotify_mask, or the mask of all FS_* event types
 * any notifier is interested in hearing for this task.
 */
#if 0
void fsnotify_recalc_task_mask(struct task_struct *task)
{
	task_lock(task);
	fsnotify_recalc_task_mask_locked(task);
	task_unlock(task);

	/* TODO: this may be the place, to handle task children. But for
	 * now, do nothing because we're tracking by task, not by inode.
	 */

	/* __fsnotify_update_child_dentry_flags(task); */
}
#endif

void fsnotify_destroy_task_mark(struct fsnotify_mark *mark)
{
	struct task_struct *task = mark->task;

  BUG_ON(!mutex_is_locked(&mark->group->mark_mutex));
  assert_spin_locked(&mark->lock);

	task_lock(task);

	// hlist_del_init_rcu(&mark->t.t_list);
	hlist_del_init_rcu(&mark->obj_list);
	mark->task = NULL;

	/*
	 * this mark is now off the task->pnotify_marks list and we
	 * hold the task->alloc_lock, so this is the perfect time to update the
	 * task->pnotify_mask
	 */
	task->pnotify_mask = fsnotify_recalc_mask(&task->pnotify_marks);
	task_unlock(task);
	put_task_struct(task);
}

/*
 * Given an task, destroy all of the marks associated with that task.
 */
void fsnotify_clear_marks_by_task(struct task_struct *task)
{
	struct fsnotify_mark *mark, *lmark;
	struct hlist_node *n;
	LIST_HEAD(free_list);

	task_lock(task);
	hlist_for_each_entry_safe(mark, n, &task->pnotify_marks, obj_list) {
    list_add(&mark->free_list, &free_list);
    hlist_del_init_rcu(&mark->obj_list);
    fsnotify_get_mark(mark);
	}
	task_unlock(task);

	list_for_each_entry_safe(mark, lmark, &free_list, free_list) {
    pnotify_create_process_exit_event(task, mark, mark->group);
  }

	fsnotify_destroy_marks(&free_list);
}

/*
 * Given a group clear all of the inode marks associated with that group.
 */
void fsnotify_clear_task_marks_by_group(struct fsnotify_group *group)
{
	fsnotify_clear_marks_by_group_flags(group, FSNOTIFY_MARK_FLAG_TASK);
}

/*
 * given a group and task, find the mark associated with that combination.
 * if found take a reference to that mark and return it, else return NULL
 */
struct fsnotify_mark *fsnotify_find_task_mark(struct fsnotify_group *group,
					     struct task_struct *task)
{
	struct fsnotify_mark *mark;

	task_lock(task);
	mark = fsnotify_find_mark(&task->pnotify_marks, group);
	task_unlock(task);

	return mark;
}

/*
 * If we are setting a mark mask on an task mark we should pin the task
 * in memory.
 *
 * TODO: or maybe we really should NOT. Where is is released?
 */
void fsnotify_set_task_mark_mask_locked(struct fsnotify_mark *mark,
				       __u32 mask)
{
	assert_spin_locked(&mark->lock);

	if (mask &&
	    mark->task &&
	    !(mark->flags & FSNOTIFY_MARK_FLAG_OBJECT_PINNED)) {
		mark->flags |= FSNOTIFY_MARK_FLAG_OBJECT_PINNED;
		get_task_struct(mark->task);
		/*
		 * we shouldn't be able to get here if the task wasn't
		 * already safely held in memory.  But bug in case it
		 * ever is wrong.
		 */
		BUG_ON(!mark->task);
	}
}

/*
 * Attach an initialized mark to a given task.
 * These marks may be used for the fsnotify backend to determine which
 * event types should be delivered to which group and for which tasks.  These
 * marks are ordered according to priority, highest number first, and then by
 * the group's location in memory.
 */
int fsnotify_add_task_mark(struct fsnotify_mark *mark,
			   struct fsnotify_group *group,
			   struct task_struct *task,
			   int allow_dups)
{
#if 0
	struct fsnotify_mark *lmark;
	struct hlist_node *node, *last = NULL;
	int ret = 0;

	mark->flags |= FSNOTIFY_MARK_FLAG_TASK;

	assert_spin_locked(&mark->lock);

  // KB_TODO 
	// assert_spin_locked(&group->mark_lock);

	task_lock(task);

	mark->task = task;

	/* is mark the first mark? */
	if (hlist_empty(&task->pnotify_marks)) {
		hlist_add_head_rcu(&mark->t.t_list, &task->pnotify_marks);
		goto out;
	}

	/* should mark be in the middle of the current list? */
	hlist_for_each_entry(lmark, &task->pnotify_marks, t.t_list) {
		last = node;

		if ((lmark->group == group) && !allow_dups) {
			ret = -EEXIST;
			goto out;
		}

		if (mark->group->priority < lmark->group->priority)
			continue;

		if ((mark->group->priority == lmark->group->priority) &&
		    (mark->group < lmark->group))
			continue;

		hlist_add_before_rcu(&mark->t.t_list, &lmark->t.t_list);
		goto out;
	}

	BUG_ON(last == NULL);
	/* mark should be the last entry.  last is the current last entry */
  // KB_TODO: need to figure out the next call
	// hlist_add_after_rcu(last, &mark->t.t_list);
out:
	fsnotify_recalc_task_mask_locked(task);
	task_unlock(task);

	return ret;
#endif
	int ret;

	mark->flags |= FSNOTIFY_MARK_FLAG_TASK;

	BUG_ON(!mutex_is_locked(&group->mark_mutex));
	assert_spin_locked(&mark->lock);

	// spin_lock(&inode->i_lock);
    task_lock(task);
	mark->task = task;
	ret = fsnotify_add_mark_list(&task->pnotify_marks, mark,
				     allow_dups);
	task->pnotify_mask = fsnotify_recalc_mask(&task->pnotify_marks);
	// spin_unlock(&inode->i_lock);
    task_unlock(task);

	return ret;

}
