#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

void sig_handle(int sig){
    printf("recv a signal: %d\n", sig);
}

void sig_handle2(int sig, siginfo_t *info, void *data){
    printf("recv a signal: %d with data: %s\n", sig, (char *)info->si_value.sival_ptr);
}

__attribute__((constructor))
static void init() {
    // 普通signal设置信号

    //signal(2, sig_handle);
    //signal(4, sig_handle);

    // 高级版sigaction
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, 2);
    act.sa_handler = sig_handle;
    sigaction(2, &act, NULL);

    // 屏蔽4信号
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, 4);
    sigprocmask(SIG_BLOCK, &set, NULL);

    // sigaction携带数据
    struct sigaction act2;
    memset(&act2, 0, sizeof(act2));
    sigemptyset(&act2.sa_mask);
    sigaddset(&act2.sa_mask, 4);

    //act2.sa_handler = sig_handle;
    act2.sa_sigaction = sig_handle2;
    act2.sa_flags = SA_SIGINFO;
    sigaction(5, &act2, NULL);



    printf("init finished!\n\n");
}

int main(){
    pid_t pid = getpid();
    printf("my pid is %d\n", pid);
    int err;

    err = kill(999, 2);
    printf("kill 999 2 ret %d\n", err);
    printf("error:%s\n\n", strerror(errno));

    err = kill(0, 2);
    printf("kill 0 2 ret %d\n\n", err);

    err = kill(0, 0);
    printf("kill 0 0 ret %d\n\n", err);

    err = kill(-1, 2);
    printf("kill -1 2 ret %d\n\n", err);

    err = raise(2);
    printf("raise(2) ret %d\n\n", err);

    err = kill(0, 65);
    printf("kill 0 65 ret %d\n", err);
    printf("error:%s\n\n", strerror(errno));

    err = raise(65);
    printf("raise(65) ret %d\n", err);
    printf("error:%s\n\n", strerror(errno));


    kill(0, 4);

    union sigval val;
    val.sival_ptr = "hello!";
    sigqueue(pid, 5, val);
    return 0;
}