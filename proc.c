#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <string.h>
#include <time.h>

static time_t last_cpu_time = 0;
static unsigned long last_process_cpu_time = 0;

void set_last_time() {
    last_cpu_time = time(NULL);
}

// 打印系统平均负载
void print_loadavg() {
    FILE *f = fopen("/proc/loadavg", "r");
    time_t t;
	struct tm *tm;
    char ts[16];
    char buf[256];
    int n;
    time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    printf("[time] %8s\n",ts);
	if (f) {
		memset(buf, 0, sizeof(buf));
		n = fread(buf, 1, sizeof(buf), f);
		if (n){
            printf("\n[loadavg]\n");
            printf("lavg1 lavg5 lavg15 running/total last_pid\n");
            printf("%s\n", buf);
        }
		fclose(f);
	}
}

void print_mem(pid_t pid){
    printf("\n[mem]\n");

    // 复用 FILE 指针和 buffer
    FILE *file = fopen("/proc/meminfo", "r");
    if (!file) {
        perror("can not open /proc/meminfo");
        return;
    }

    char buffer[256];
    long memory = -1;

    // 读取总内存信息
    while (fgets(buffer, sizeof(buffer), file)) {
        if (sscanf(buffer, "MemTotal: %ld kB", &memory) == 1) {
            memory *= 1024;  // 转换为字节
            break;
        }
    }
    fclose(file);
    printf("total mem: %ld bytes (%.2f GB)\n", memory, memory / (1024.0 * 1024 * 1024));

    // 如果指定了 PID，读取进程内存信息
    if (pid != 0) {
        snprintf(buffer, sizeof(buffer), "/proc/%d/status", pid);
        file = fopen(buffer, "r");
        if (!file) {
            perror("can not open process status file");
            return;
        }

        // 读取进程内存使用
        while (fgets(buffer, sizeof(buffer), file)) {
            if (sscanf(buffer, "VmRSS: %ld kB", &memory) == 1) {
                memory *= 1024;  // 转换为字节
                break;
            }
        }
        fclose(file);
        printf("pid %d used mem: %ld bytes (%.2f MB)\n", pid, memory, memory / (1024.0 * 1024));
    }
}

// 打印文件句柄限制
void print_file_handle_limit() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        printf("File Handle Limit: Soft=%ld, Hard=%ld\n", rl.rlim_cur, rl.rlim_max);
    } else {
        perror("getrlimit for RLIMIT_NOFILE failed");
    }
}

// 打印软中断
void print_soft_interrupts() {
    FILE *file = fopen("/proc/softirqs", "r");
    if (!file) {
        perror("Could not open /proc/softirqs");
        return;
    }

    char line[256];
    printf("\n[Soft Interrupts]\n");
    while (fgets(line, sizeof(line), file)) {
        printf("%s", line);
    }
    fclose(file);
}

// 打印最大进程线程数
void print_nproc_limit() {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NPROC, &rl) == 0) {
        printf("Max Process/Thread Count: Soft=%ld, Hard=%ld\n", rl.rlim_cur, rl.rlim_max);
    } else {
        perror("getrlimit for RLIMIT_NPROC failed");
    }
}

// 打印TCP backlog限制
void print_tcp_backlog() {
    FILE *file = fopen("/proc/sys/net/core/somaxconn", "r");
    if (!file) {
        perror("Could not open /proc/sys/net/core/somaxconn");
        return;
    }

    int somaxconn;
    fscanf(file, "%d", &somaxconn);
    printf("TCP Backlog (somaxconn): %d\n", somaxconn);
    fclose(file);
}

// 打印swap信息
void print_swap_info() {
    struct sysinfo info;
    if (sysinfo(&info) == 0) {
        printf("Swap: Total=%ld KB, Free=%ld KB\n", info.totalswap * info.mem_unit / 1024, info.freeswap * info.mem_unit / 1024);
    } else {
        perror("sysinfo failed");
    }
}

void get_process_cpu_time(int pid, unsigned long *total_time) {
    char stat_filepath[256];
    unsigned long utime, stime, cutime, cstime;
    snprintf(stat_filepath, sizeof(stat_filepath), "/proc/%d/stat", pid);

    FILE *file = fopen(stat_filepath, "r");
    if (!file) {
        perror("Could not open stat file");
        return;
    }

    // Skip initial fields and read utime and stime
    fscanf(file, "%*d %*s %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %lu %lu",
           &utime, &stime, &cutime, &cstime);
    fclose(file);

    *total_time = utime + stime + cutime + cstime;
}


// 打印CPU使用率
void print_cpu_usage(pid_t pid) {
    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    printf("\n[cpu]\n");
    printf("Number of CPU cores: %ld\n", nprocs);
    if(pid == 0){
        return;
    }
    unsigned long total_time = 0;
    long ticks_per_second = sysconf(_SC_CLK_TCK);
    get_process_cpu_time(pid, &total_time);
    time_t now = time(NULL);
    if(last_process_cpu_time == 0 || now - last_process_cpu_time == 0){
        last_cpu_time = now;
        last_process_cpu_time = total_time;
        return;
    }
    // Calculate CPU usage percentage based on clock ticks per second
    double cpu_usage = (100.0 * (total_time - last_process_cpu_time) / ticks_per_second)/(now - last_cpu_time);
    printf("now: %ld,last_cpu_time: %ld,total_time: %ld,ticks_per_second: %ld\n",now,last_cpu_time,total_time,ticks_per_second);
    last_cpu_time = now;
    last_process_cpu_time = total_time;
    cpu_usage = cpu_usage > 100 ? 100 : cpu_usage;

    printf("CPU usage for process %d: %.2f%%\n", pid, cpu_usage);

}

void print_proc_limits(){
    printf("[sys limits]\n");
    print_file_handle_limit();
    print_nproc_limit();
    print_swap_info();
}
    

// 主函数
void print_system_limits(pid_t pid) {
    print_loadavg();
    print_proc_limits();
    print_cpu_usage(pid);
    print_mem(pid);
    print_soft_interrupts();
}

