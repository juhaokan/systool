/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __SYSTOOL_H
#define __SYSTOOL_H

#define PATH_MAX	4096
#define TASK_COMM_LEN	16

enum op {
	READ,
	WRITE,
};

struct file_id {
	__u64 inode;
	__u32 dev;
	__u32 rdev;
	__u32 pid;
	__u32 tid;
};

struct file_stat {
	__u64 reads;
	__u64 read_bytes;
	__u64 writes;
	__u64 write_bytes;
	__u32 pid;
	__u32 tid;
	char filename[PATH_MAX];
	char dir[PATH_MAX];
	char comm[TASK_COMM_LEN];
	char type;
};

struct ip_key_t {
	unsigned __int128 saddr;
	unsigned __int128 daddr;
	__u32 pid;
	char name[TASK_COMM_LEN];
	__u16 lport;
	__u16 dport;
	__u16 family;
};

struct traffic_t {
	size_t sent;
	size_t received;
};


#endif /* __SYSTOOL_H */
