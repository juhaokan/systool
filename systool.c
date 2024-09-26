#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "systool.h"
#include "systool.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"
#include "proc.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240

#define IPV4 0
#define PORT_LENGTH 5

enum SORT {
	ALL,
	READS,
	WRITES,
	RBYTES,
	WBYTES,
};

enum TYPE{
    TYPE_ALL,
    TYPE_MYSQL,
};

struct info_t {
	struct ip_key_t key;
	struct traffic_t value;
};

static volatile sig_atomic_t exiting = 0;

static pid_t target_pid = 0;
static bool clear_screen = true;
static bool regular_file_only = true;
static int output_rows = 20;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;
static int type = TYPE_ALL;

const char argp_program_doc[] =
"Trace file reads/writes by process.\n"
"\n"
"USAGE: filetop [-h] [-p PID] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    filetop            # file I/O top, refresh every 1s\n"
"    filetop -p 1216    # only trace PID 1216\n"
"    filetop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "pid", 'p', "PID", 0, "Process ID to trace", 0 },
	{ "noclear", 'C', NULL, 0, "Don't clear the screen", 0 },
    { "type", 't', "TYPE", 0, "Type of pid to trace", 0 },
	{ "verbose", 'v', NULL, 0, "Verbose debug output", 0 },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help", 0 },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long pid;

	switch (key) {
	case 'p':
		errno = 0;
		pid = strtol(arg, NULL, 10);
		printf("pid: %ld\n", pid);
		if (errno || pid <= 0) {
			warn("invalid PID: %s\n", arg);
			argp_usage(state);
		}
		target_pid = pid;
		break;
	case 'C':
		clear_screen = false;
		break;
	case 'v':
		verbose = true;
		break;
    case 't':
        if (!strcmp(arg, "mysql")) {
            type = TYPE_MYSQL;
        } 
        break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static char* get_file_type(char* filename){
	 // 获取文件名的后缀
    const char *dot = strrchr(filename, '.');
    
    if (strstr(filename, "ibdata") != NULL) {
        return "IBDATA";
    } else if (strstr(filename, "ibtmp") != NULL) {
        return "INNODB TMP";
    } else if(strstr(filename, "binlog") != NULL) {
        return "BIN LOG";
    } else if(strstr(filename, "ib_redo") != NULL) {
		return "REDO LOG";
	} else if(!dot){
		return "UNKNOWN";
	} else if (strcmp(dot, ".frm") == 0) {
        return "FRM";
    } else if (strcmp(dot, ".ibd") == 0) {
        return "TABLE";
    } else if (strcmp(dot, ".opt") == 0) {
        return "OPTION FILE";
    } else if (strcmp(dot, ".log") == 0) {
        return "LOG";
    } else if (strcmp(dot, ".dblwr") == 0) {
		return "Doublewrite Buffer";
	}else {
        return "UNKNOWN";
    }
}

static int print_iostat(struct systool_bpf *obj)
{
	struct file_id key, *prev_key = NULL;
	static struct file_stat values[OUTPUT_ROWS_LIMIT];
	int i, err = 0, rows = 0;
	int fd = bpf_map__fd(obj->maps.entries);

	printf("\n[IO]\n");
	if(type == TYPE_MYSQL){
		printf("%-7s %-16s %-6s %-6s %-7s %-7s %1s %-20s %-20s %-20s\n",
	       "TID", "COMM", "READS", "WRITES", "R_Kb", "W_Kb", "T", "FILE","DIR","FILETYPE");
	}else{
		printf("%-7s %-16s %-6s %-6s %-7s %-7s %1s %s %-20s\n",
	       "TID", "COMM", "READS", "WRITES", "R_Kb", "W_Kb", "T", "FILE","DIR");
	}
	

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_lookup_elem(fd, &key, &values[rows++]);
		if (err) {
			warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}

	rows = rows < output_rows ? rows : output_rows;
	for (i = 0; i < rows; i++){
		if(type == TYPE_MYSQL){
			printf("%-7d %-16s %-6lld %-6lld %-7lld %-7lld %c %-20s %-20s %-20s\n",
		       values[i].tid, values[i].comm, values[i].reads, values[i].writes,
		       values[i].read_bytes / 1024, values[i].write_bytes / 1024,
		       values[i].type, values[i].filename,values[i].dir, get_file_type(values[i].filename));
		}
		else{
			printf("%-7d %-16s %-6lld %-6lld %-7lld %-7lld %c %-20s %-20s\n",
		       values[i].tid, values[i].comm, values[i].reads, values[i].writes,
		       values[i].read_bytes / 1024, values[i].write_bytes / 1024,
		       values[i].type, values[i].filename,values[i].dir);
		}
	}
		

	printf("\n");
	prev_key = NULL;

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_delete_elem(fd, &key);
		if (err) {
			warn("bpf_map_delete_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}
	return err;
}

static int print_tcpstat(struct systool_bpf *obj)
{
	char buf[256];
	struct ip_key_t key, *prev_key = NULL;
	static struct info_t infos[OUTPUT_ROWS_LIMIT];
	int i, err = 0;
	int fd = bpf_map__fd(obj->maps.ip_map);
	int rows = 0;
	bool ipv6_header_printed = false;
	int pid_max_fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	int pid_maxlen = read(pid_max_fd, buf, sizeof buf) - 1;

	if (pid_maxlen < 6)
		pid_maxlen = 6;
	close(pid_max_fd);

	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &infos[rows].key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_lookup_elem(fd, &infos[rows].key, &infos[rows].value);
		if (err) {
			warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &infos[rows].key;
		rows++;
	}
	printf("\n[TCP]\n");
	print_tcp_backlog();
	printf("%-*s %-12s %-21s %-21s %6s %6s\n",
				 pid_maxlen, "PID", "COMM", "LADDR", "RADDR",
				 "RX_KB", "TX_KB");

	rows = rows < output_rows ? rows : output_rows;
	for (i = 0; i < rows; i++) {
		/* Default width to fit IPv4 plus port. */
		int column_width = 21;
		struct ip_key_t *key = &infos[i].key;
		struct traffic_t *value = &infos[i].value;

		if (key->family == AF_INET6) {
			/* Width to fit IPv6 plus port. */
			column_width = 51;
			if (!ipv6_header_printed) {
				printf("\n%-*s %-12s %-51s %-51s %6s %6s\n",
							pid_maxlen, "PID", "COMM", "LADDR6",
							"RADDR6", "RX_KB", "TX_KB");
				ipv6_header_printed = true;
			}
		}

		char saddr[INET6_ADDRSTRLEN];
		char daddr[INET6_ADDRSTRLEN];

		inet_ntop(key->family, &key->saddr, saddr, INET6_ADDRSTRLEN);
		inet_ntop(key->family, &key->daddr, daddr, INET6_ADDRSTRLEN);

		/*
		 * A port is stored in u16, so highest value is 65535, which is 5
		 * characters long.
		 * We need one character more for ':'.
		 */
		size_t size = INET6_ADDRSTRLEN + PORT_LENGTH + 1;

		char saddr_port[size];
		char daddr_port[size];

		snprintf(saddr_port, size, "%s:%d", saddr, key->lport);
		snprintf(daddr_port, size, "%s:%d", daddr, key->dport);

		printf("%-*d %-12.12s %-*s %-*s %6ld %6ld\n",
					 pid_maxlen, key->pid, key->name,
					 column_width, saddr_port,
					 column_width, daddr_port,
					 value->received / 1024, value->sent / 1024);
	}

	printf("\n");

	prev_key = NULL;
	while (1) {
		err = bpf_map_get_next_key(fd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_delete_elem(fd, &key);
		if (err) {
			warn("bpf_map_delete_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;
	}

	return err;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct systool_bpf *obj;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = systool_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	obj->rodata->target_pid = target_pid;
	obj->rodata->regular_file_only = regular_file_only;

	err = systool_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = systool_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (1) {
		sleep(interval);

		if (clear_screen) {
			err = system("clear");
			if (err)
				goto cleanup;
		}
		print_system_limits(target_pid);
		err = print_iostat(obj);
		if (err)
			goto cleanup;
		err = print_tcpstat(obj);
		if (err)
			goto cleanup;
		count--;
		if (exiting || !count)
			goto cleanup;
	}

cleanup:
	systool_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
