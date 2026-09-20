/*
 * 通用 OpenHarmony 本机 datagram 客户端（§9.1 native_unix 传输载体）。
 *
 * 设计约束（§7.2 / §9.1）：
 * - 不调用 shell，不执行派生命令；只读 payload 文件并向声明 socket 发送；
 * - 每个 socket()/setsockopt()/setresgid/setresuid/connect/sendto/recv/close
 *   的返回码与 errno 逐项输出（JSON 行），"客户端发送失败"与"服务拒绝"必须可分；
 * - --patch-event-credentials：EventRaw datagram 头部 UID/PID(@4+59/@4+63) 回填为
 *   本进程真实凭据（服务端校验 header == SCM_CREDENTIALS，实机验证有效）；
 * - 支持多帧序列发送（--delay-ms），用于需要帧对的协议（如 SP_daemon 文本协议）。
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>

static void report(const char *call, long rc, int err, const char *detail) {
    printf("{\"call\":\"%s\",\"rc\":%ld,\"errno\":%d,\"detail\":\"%s\"}\n",
           call, rc, err, detail ? detail : "");
}

static int read_payload(const char *path, unsigned char **out, size_t *size) {
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) return errno;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return errno; }
    long length = ftell(fp);
    if (length < 0 || length > 1024 * 1024) { fclose(fp); return EFBIG; }
    rewind(fp);
    unsigned char *buf = (unsigned char *)malloc((size_t)length);
    if (buf == NULL && length != 0) { fclose(fp); return ENOMEM; }
    if (length != 0 && fread(buf, 1, (size_t)length, fp) != (size_t)length) {
        int saved = errno; free(buf); fclose(fp); return saved ? saved : EIO;
    }
    fclose(fp); *out = buf; *size = (size_t)length; return 0;
}

static int patch_event_credentials(unsigned char *payload, size_t payload_size) {
    if (payload == NULL || payload_size < 71) return EINVAL;
    uint32_t uid = (uint32_t)getuid();
    uint32_t pid = (uint32_t)getpid();
    memcpy(payload + 4 + 59, &uid, sizeof(uid));
    memcpy(payload + 4 + 63, &pid, sizeof(pid));
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s /dev/unix/socket/name payload.bin [--patch-event-credentials] [--delay-ms N] [--frames N]\n", argv[0]);
        return 2;
    }
    const char *socket_path = argv[1];
    const char *payload_path = argv[2];
    int patch_credentials = 0;
    int delay_ms = 0;
    int frames = 1;
    uid_t drop_uid = 0, drop_gid = 0;
    int drop_privs = 0;
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--patch-event-credentials") == 0) patch_credentials = 1;
        else if (i + 1 < argc && strcmp(argv[i], "--delay-ms") == 0) delay_ms = atoi(argv[++i]);
        else if (i + 1 < argc && strcmp(argv[i], "--frames") == 0) frames = atoi(argv[++i]);
        else if (i + 2 < argc && strcmp(argv[i], "--drop-privs") == 0) {
            drop_uid = (uid_t)atoi(argv[++i]);
            drop_gid = (gid_t)atoi(argv[++i]);
            drop_privs = 1;
        }
    }
    if (drop_privs) {
        /* 身份阶梯（§12.2）：root 证据封顶 grade C；降权到非特权身份
         * 才能把攻击者模型拉回真实（HAP/app 侧无 root）。降权必须最先做，
         * 且 setres* 失败立即退出——绝不允许带未降权身份出"非 root"报告。 */
        if (setresgid(drop_gid, drop_gid, drop_gid) != 0) {
            report("setresgid", -1, errno, "drop-privs refused; aborting");
            return 8;
        }
        if (setresuid(drop_uid, drop_uid, drop_uid) != 0) {
            report("setresuid", -1, errno, "drop-privs refused; aborting");
            return 8;
        }
        char buf[64];
        snprintf(buf, sizeof(buf), "uid=%u gid=%u", getuid(), getgid());
        report("drop_privs", 0, 0, buf);
    }
    if (frames < 1) frames = 1;
    if (frames > 8) frames = 8;
    if (socket_path[0] != '/') {
        fprintf(stderr, "socket path must be absolute\n");
        return 2;
    }
    unsigned char *payload = NULL; size_t payload_size = 0;
    int rc = read_payload(payload_path, &payload, &payload_size);
    if (rc != 0) { report("read_payload", -1, rc, payload_path); return 3; }
    if (patch_credentials) {
        rc = patch_event_credentials(payload, payload_size);
        if (rc != 0) { report("patch_credentials", -1, rc, NULL); free(payload); return 3; }
        report("patch_credentials", 0, 0, "uid/pid patched at header+59/63");
    }
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { report("socket", -1, errno, "AF_UNIX/SOCK_DGRAM"); free(payload); return 4; }
    report("socket", fd, 0, "AF_UNIX/SOCK_DGRAM");
    struct sockaddr_un address; memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(socket_path) >= sizeof(address.sun_path)) {
        report("address_len", -1, ENAMETOOLONG, socket_path); close(fd); free(payload); return 5;
    }
    strcpy(address.sun_path, socket_path);
    for (int f = 0; f < frames; f++) {
        if (f > 0 && delay_ms > 0) usleep(delay_ms * 1000);
        ssize_t sent = sendto(fd, payload, payload_size, 0,
                              (struct sockaddr *)&address, sizeof(address));
        if (sent < 0) {
            report("sendto", -1, errno, "frame");
            char buf[32]; snprintf(buf, sizeof(buf), "frame=%d", f);
            report("result", 1, errno, buf);
            close(fd); free(payload); return 6;
        }
        if ((size_t)sent != payload_size) {
            report("sendto", (long)sent, 0, "short datagram");
            close(fd); free(payload); return 7;
        }
        char buf[48]; snprintf(buf, sizeof(buf), "frame=%d bytes=%zu", f, (size_t)sent);
        report("sendto", (long)sent, 0, buf);
    }
    report("result", 0, 0, "delivered");
    close(fd); free(payload);
    return 0;
}
