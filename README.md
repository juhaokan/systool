# SYSTOOL 系统诊断工具

## 功能示例
执行该工具会输出系统的网络IO，CPU，内存，磁盘IO，以及系统设置信息，示例
```
./systool 
[time] 16:34:49

[loadavg]
lavg1 lavg5 lavg15 running/total last_pid
1.25 1.16 1.10 3/977 361123

[sys limits]
File Handle Limit: Soft=65535, Hard=65535
Max Process/Thread Count: Soft=127314, Hard=127314
Swap: Total=0 KB, Free=0 KB

[cpu]
Number of CPU cores: 16

[mem]
total mem: 33435029504 bytes (31.14 GB)

[Soft Interrupts]
                    CPU0       CPU1       CPU2       CPU3       CPU4       CPU5       CPU6       CPU7       CPU8       CPU9       CPU10      CPU11      CPU12      CPU13      CPU14      CPU15
          HI:          0          0          0          3          0          0          0          1          0          0          0          0          0          0          0          0
       TIMER:     414614    2140475    1361943    1045494     837807     867469     942844    1274911     593833     556297     532507     529932     553454     540665     590431     526852
      NET_TX:          0          1          0          3          1          0          1          0          0          0          0          0          0          0          2          0
      NET_RX:      13370      27527      22822      18238      16728      17221      14824    3243202      13727     184892      14061      15168      17939      15081      17549      17527
       BLOCK:      14342      62885     227192      44095      34122      31675      33098      31126      22577      25345      17978      23693      22172      19726      24227      18997
    IRQ_POLL:          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0          0
     TASKLET:          1          6         14         74          1          2         13        102          0      19192          0          4          1          5          1          5
       SCHED:    5258790    4929113    4196276    3849369    3064322    2675791    2485626    2727296    2154482    2171410    2013732    1934854    2017065    1958664    1993159    1948878
     HRTIMER:          0          1          1          0          0          0          0       1181          0          1          1          0          0          0          0          0
         RCU:    1486715    2880117    2664294    2604614    2268313    2119654    2047808    3614672    1779038    1790868    1717316    1677229    1727225    1677097    1697171    1683012

[IO]
TID     COMM             READS  WRITES R_Kb    W_Kb    T FILE DIR
361123  clear            2      0      60      0       R xterm                x
361120  systool          4      0      4       0       R softirqs             /
335343  DefaultDispatch  2      0      15      0       R accepted             consentOptions
361123  sh               4      0      1       0       R libc-2.28.so         lib64
359624  Action Updater   0      1      0       0       R idea.log             log
361122  postgres         1      0      0       0       R pg_filenode.map      1
361122  postgres         1      0      4       0       R PG_VERSION           1
361120  systool          1      0      8       0       R online               cpu
359624  Action Updater   2      0      15      0       R accepted             consentOptions
361123  sh               3      0      0       0       R clear                bin
361120  systool          1      0      1       0       R meminfo              /
361123  sh               1      0      0       0       R libdl-2.28.so        lib64
361122  postgres         41     0      164     0       R pg_internal.init     1
361120  systool          2      0      2       0       R loadavg              /
361120  systool          1      0      0       0       R pid_max              kernel
361123  systool          4      0      1       0       R ld-2.28.so           lib64
361122  postgres         1      0      0       0       R pg_filenode.map      global
361123  systool          3      0      0       0       R bash                 bin
361122  postgres         8      0      32      0       R pg_internal.init     global
360326  Action Updater   0      1      0       0       R idea.log             log


[TCP]
TCP Backlog (somaxconn): 128
PID     COMM         LADDR                 RADDR                  RX_KB  TX_KB
359963  sshd         10.18.215.118:22      10.18.102.194:52691        0      1

```

## 参数说明
```
[root@localhost tool]# ./systool --help
Usage: systool [OPTION...]
Trace file reads/writes by process.

USAGE: filetop [-h] [-p PID] [interval] [count]

EXAMPLES:
    filetop            # file I/O top, refresh every 1s
    filetop -p 1216    # only trace PID 1216
    filetop 5 10       # 5s summaries, 10 times

  -C, --noclear              Don't clear the screen
  -p, --pid=PID              Process ID to trace
  -t, --type=TYPE            Type of pid to trace
  -v, --verbose              Verbose debug output
  -?, --help                 Give this help list
      --usage                Give a short usage message

Mandatory or optional arguments to long options are also mandatory or optional

```
+ `-C` 不清理屏幕
+ `-p` 指定进程ID
+ `-t` 指定进程类型,目前支持`mysql`类型
+ `-v` 输出调试信息

## 快速开始
编译需要安装`clang`及`llvm`
```
git clone https://github.com/juhaokan/systool.git
cd systool
make 
```



