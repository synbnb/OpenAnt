// Minimal, reviewable native carrier helper for OpenHarmony SOCK_DGRAM Unix
// sockets. It reads an exact payload file and sends one datagram; it does not
// invoke a shell, execute a command, or mutate any other device state.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>

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
    // EventRaw's datagram format stores the packed header after the initial
    // int32 block length.  UID/PID are at header offsets 59 and 63.  The
    // receiver compares them with SCM_CREDENTIALS, so patching them here
    // makes the reviewed carrier valid without trusting host-side values.
    if (payload == NULL || payload_size < 71) return EINVAL;
    uint32_t uid = (uint32_t)getuid();
    uint32_t pid = (uint32_t)getpid();
    memcpy(payload + 4 + 59, &uid, sizeof(uid));
    memcpy(payload + 4 + 63, &pid, sizeof(pid));
    return 0;
}

int main(int argc, char **argv) {
    int patch_credentials = 0;
    if (argc == 4 && strcmp(argv[3], "--patch-event-credentials") == 0) {
        patch_credentials = 1;
    } else if (argc != 3) {
        fprintf(stderr, "usage: %s /dev/unix/socket/name payload-file [--patch-event-credentials]\n", argv[0]);
        return 2;
    }
    if (argv[1][0] != '/') {
        fprintf(stderr, "socket path must be absolute\n");
        return 2;
    }
    unsigned char *payload = NULL; size_t payload_size = 0;
    int rc = read_payload(argv[2], &payload, &payload_size);
    if (rc != 0) { fprintf(stderr, "read payload: %s\n", strerror(rc)); return 3; }
    if (patch_credentials) {
        rc = patch_event_credentials(payload, payload_size);
        if (rc != 0) { free(payload); fprintf(stderr, "patch credentials: %s\n", strerror(rc)); return 3; }
    }
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { free(payload); perror("socket"); return 4; }
    struct sockaddr_un address; memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(argv[1]) >= sizeof(address.sun_path)) {
        close(fd); free(payload); fprintf(stderr, "socket path too long\n"); return 5;
    }
    strcpy(address.sun_path, argv[1]);
    ssize_t sent = sendto(fd, payload, payload_size, 0,
                          (struct sockaddr *)&address, sizeof(address));
    int saved = errno; close(fd); free(payload);
    if (sent < 0) { errno = saved; perror("sendto"); return 6; }
    if ((size_t)sent != payload_size) { fprintf(stderr, "short datagram\n"); return 7; }
    printf("sent=%zu\n", payload_size); return 0;
}
