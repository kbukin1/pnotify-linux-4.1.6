#include <linux/fsnotify_backend.h>
#include <linux/pnotify.h>
#include <linux/slab.h> /* struct kmem_cache */

extern struct kmem_cache *pnotify_event_priv_cachep;
extern struct kmem_cache *pnotify_wd_pid_cachep __read_mostly;

struct pnotify_event_info {
	struct fsnotify_event fse;
	int wd;
	u32 sync_cookie;

	u32		tgid;
	u32		pid;
	u32		ppid;
	u64		jiffies;
	unsigned long	inode_num;	/* KB_TODO probalby need to use platform-independent type */
	signed long	status;		/* KB_TODO probalby need to use platform-independent type */

	int name_len;
	char *name;
};

struct pnotify_inode_mark {
	struct fsnotify_mark fsn_mark;
	u32 wd;
};

static inline struct pnotify_event_info *PNOTIFY_E(struct fsnotify_event *fse)
{
	return container_of(fse, struct pnotify_event_info, fse);
}

struct pnotify_wd_pid_struct {
	struct list_head pnotify_wd_pid_list_item;
	u32 wd;
	u32 pid;
};

extern void pnotify_ignored_and_remove_idr(struct fsnotify_mark *fsn_mark,
					   struct fsnotify_group *group);
extern int pnotify_handle_event(struct fsnotify_group *group,
				struct inode *inode,
				struct fsnotify_mark *inode_mark,
				struct fsnotify_mark *vfsmount_mark,
				u32 mask, void *data, int data_type,
				const unsigned char *file_name, u32 cookie,
        pid_t tgid, pid_t pid, pid_t ppid, 
        struct path *path, unsigned long status);

extern const struct fsnotify_ops pnotify_fsnotify_ops;
