#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 获取系统总内存大小
long get_total_memory() {
    FILE *file = fopen("/proc/meminfo", "r");
    if (!file) {
        perror("无法打开 /proc/meminfo");
        return -1;
    }

    char buffer[256];
    long total_memory = -1;
    
    // 读取文件的每一行
    while (fgets(buffer, sizeof(buffer), file)) {
        if (sscanf(buffer, "MemTotal: %ld kB", &total_memory) == 1) {
            total_memory *= 1024;  // 转换为字节
            break;
        }
    }

    fclose(file);
    return total_memory;
}

// 获取指定进程的内存使用大小
long get_process_memory_usage(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *file = fopen(path, "r");
    if (!file) {
        perror("无法打开进程状态文件");
        return -1;
    }

    char buffer[256];
    long memory_usage = -1;

    // 读取文件的每一行
    while (fgets(buffer, sizeof(buffer), file)) {
        if (sscanf(buffer, "VmRSS: %ld kB", &memory_usage) == 1) {
            memory_usage *= 1024;  // 转换为字节
            break;
        }
    }

    fclose(file);
    return memory_usage;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "用法: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);

    long total_memory = get_total_memory();
    if (total_memory != -1) {
        printf("系统总内存: %ld 字节 (%.2f GB)\n", total_memory, total_memory / (1024.0 * 1024 * 1024));
    }

    long process_memory = get_process_memory_usage(pid);
    if (process_memory != -1) {
        printf("进程 %d 使用的内存: %ld 字节 (%.2f MB)\n", pid, process_memory, process_memory / (1024.0 * 1024));
    }

    return 0;
}

