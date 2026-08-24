#include <stdio.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

int main(void)
{
    struct utsname info;
    if (uname(&info) != 0) {
        return 2;
    }

    printf("openant_native_smoke pid=%d uid=%d euid=%d machine=%s sysname=%s release=%s\n",
        (int)getpid(), (int)getuid(), (int)geteuid(), info.machine, info.sysname, info.release);
    return 0;
}
