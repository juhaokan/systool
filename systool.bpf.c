#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "systool.h"
#include "stat.h"

/* Taken from kernel include/linux/socket.h. */
#define AF_INET		2	/* Internet IP Protocol 	*/
#define AF_INET6	10	/* IP version 6			*/
#define MAX_ENTRIES	10240

const volatile bool filter_cg = false;
const volatile int target_family = -1;
const volatile pid_t target_pid = 0;
const volatile bool regular_file_only = true;
static struct file_stat zero_value = {};

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_key_t);
	__type(value, struct traffic_t);
} ip_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct file_id);
	__type(value, struct file_stat);
} entries SEC(".maps");

static void get_file_path(struct file *file, char *buf, size_t size)
{
	struct qstr dname;

	dname = BPF_CORE_READ(file, f_path.dentry, d_name);
	bpf_probe_read_kernel(buf, size, dname.name);
}

static void get_file_dir(struct file *file, char *buf, size_t size) {
    struct dentry *dentry;
    struct dentry *parent_dentry;
    struct qstr parent_dname;
    char name[PATH_MAX];
    
    // Read dentry structure for the file
    dentry = BPF_CORE_READ(file, f_path.dentry);

    // Read parent dentry structure
    parent_dentry = BPF_CORE_READ(dentry, d_parent);

    // Read parent dname structure
    parent_dname = BPF_CORE_READ(parent_dentry, d_name);

    // Copy the name of the parent directory to the buffer
    // Ensure to limit the copy size to avoid buffer overflows
    bpf_probe_read_kernel(buf, size, parent_dname.name);
}

static int probe_entry(struct pt_regs *ctx, struct file *file, size_t count, enum op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	int mode;
	struct file_id key = {};
	struct file_stat *valuep;

	if (target_pid && target_pid != pid)
		return 0;

	mode = BPF_CORE_READ(file, f_inode, i_mode);
	if (regular_file_only && !S_ISREG(mode))
		return 0;

	key.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
	key.rdev = BPF_CORE_READ(file, f_inode, i_rdev);
	key.inode = BPF_CORE_READ(file, f_inode, i_ino);
	key.pid = pid;
	key.tid = tid;
	valuep = bpf_map_lookup_elem(&entries, &key);
	if (!valuep) {
		bpf_map_update_elem(&entries, &key, &zero_value, BPF_ANY);
		valuep = bpf_map_lookup_elem(&entries, &key);
		if (!valuep)
			return 0;
		valuep->pid = pid;
		valuep->tid = tid;
		bpf_get_current_comm(&valuep->comm, sizeof(valuep->comm));
		get_file_path(file, valuep->filename, sizeof(valuep->filename));
		get_file_dir(file, valuep->dir, sizeof(valuep->dir));
		if (S_ISREG(mode)) {
			valuep->type = 'R';
		} else if (S_ISSOCK(mode)) {
			valuep->type = 'S';
		} else {
			valuep->type = 'O';
		}
	}
	if (op == READ) {
		valuep->reads++;
		valuep->read_bytes += count;
	} else {	/* op == WRITE */
		valuep->writes++;
		valuep->write_bytes += count;
	}
	return 0;
};

SEC("kprobe/vfs_read")
int BPF_KPROBE(vfs_read_entry, struct file *file, char *buf, size_t count, loff_t *pos)
{
	return probe_entry(ctx, file, count, READ);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(vfs_write_entry, struct file *file, const char *buf, size_t count, loff_t *pos)
{
	return probe_entry(ctx, file, count, WRITE);
}

static int probe_ip(bool receiving, struct sock *sk, size_t size)
{
	struct ip_key_t ip_key = {};
	struct traffic_t *trafficp;
	u16 family;
	u32 pid;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;
	if (target_pid  && target_pid != pid)
		return 0;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (target_family != -1 && target_family != family)
		return 0;

	/* drop */
	if (family != AF_INET && family != AF_INET6)
		return 0;

	ip_key.pid = pid;
	bpf_get_current_comm(&ip_key.name, sizeof(ip_key.name));
	ip_key.lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	ip_key.dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	ip_key.family = family;

	if (family == AF_INET) {
		bpf_probe_read_kernel(&ip_key.saddr,
				      sizeof(sk->__sk_common.skc_rcv_saddr),
				      &sk->__sk_common.skc_rcv_saddr);
		bpf_probe_read_kernel(&ip_key.daddr,
				      sizeof(sk->__sk_common.skc_daddr),
				      &sk->__sk_common.skc_daddr);
	} else {
		/*
		 * family == AF_INET6,
		 * we already checked above family is correct.
		 */
		bpf_probe_read_kernel(&ip_key.saddr,
				      sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32),
				      &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		bpf_probe_read_kernel(&ip_key.daddr,
				      sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),
				      &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	trafficp = bpf_map_lookup_elem(&ip_map, &ip_key);
	if (!trafficp) {
		struct traffic_t zero;

		if (receiving) {
			zero.sent = 0;
			zero.received = size;
		} else {
			zero.sent = size;
			zero.received = 0;
		}

		bpf_map_update_elem(&ip_map, &ip_key, &zero, BPF_NOEXIST);
	} else {
		if (receiving)
			trafficp->received += size;
		else
			trafficp->sent += size;

		bpf_map_update_elem(&ip_map, &ip_key, trafficp, BPF_EXIST);
	}

	return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	return probe_ip(false, sk, size);
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;

	return probe_ip(true, sk, copied);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
