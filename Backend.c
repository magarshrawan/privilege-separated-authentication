#define _GNU_SOURCE
#include "Protocol.h"

#include <crypt.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static void secure_zero(void *p, size_t n)
{
    volatile unsigned char *v = p;
    while (n-- != 0)
        *v++ = 0;
}

static int parse_id(const char *text, unsigned long *result)
{
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 10);
    if (errno || *text == '\0' || *end != '\0' || value > UINT_MAX)
        return -1;
    *result = value;
    return 0;
}

static int load_verifier(const char *path, const char *username,
                         char *hash, size_t hash_capacity)
{
    FILE *file = fopen(path, "re");
    if (!file)
        return -1;
    struct stat info;
    if (fstat(fileno(file), &info) == -1 ||
        info.st_uid != 0 || (info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        fclose(file);
        errno = EPERM;
        return -1;
    }

    char line[512];
    int found = -1;
    while (fgets(line, sizeof(line), file)) {
        char *separator = strchr(line, ':');
        if (!separator)
            continue;
        *separator++ = '\0';
        separator[strcspn(separator, "\r\n")] = '\0';
        if (strcmp(line, username) == 0 && strlen(separator) < hash_capacity) {
            strcpy(hash, separator);
            found = 0;
            break;
        }
    }
    secure_zero(line, sizeof(line));
    fclose(file);
    if (found != 0)
        errno = ENOENT;
    return found;
}

static int make_listener(const char *path, uid_t allowed_uid)
{
    if (strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd == -1)
        return -1;

    struct sockaddr_un address = { .sun_family = AF_UNIX };
    strcpy(address.sun_path, path);
    (void)unlink(path);
    mode_t old_mask = umask(0077);
    int result = bind(fd, (struct sockaddr *)&address, sizeof(address));
    umask(old_mask);
    if (result == -1 || chown(path, allowed_uid, (gid_t)-1) == -1 ||
        chmod(path, 0600) == -1 || listen(fd, 4) == -1) {
        close(fd);
        return -1;
    }
    return fd;
}

static int constant_time_equal(const char *left, const char *right, size_t length)
{
    unsigned char difference = 0;
    for (size_t i = 0; i < length; ++i)
        difference |= (unsigned char)left[i] ^ (unsigned char)right[i];
    return difference == 0;
}

static int receive_request(int fd, struct auth_request *request, int *memory_fd)
{
    struct iovec io = { .iov_base = request, .iov_len = sizeof(*request) };
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr message = {
        .msg_iov = &io, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)
    };
    ssize_t count = recvmsg(fd, &message, MSG_CMSG_CLOEXEC);
    if (count != (ssize_t)sizeof(*request) ||
        (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)))
        return -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
        cmsg->cmsg_len != CMSG_LEN(sizeof(int)))
        return -1;
    memcpy(memory_fd, CMSG_DATA(cmsg), sizeof(*memory_fd));
    return 0;
}

static int valid_request(const struct auth_request *request)
{
    return request->magic == AUTH_MAGIC &&
           request->version == AUTH_VERSION &&
           request->operation == AUTH_OP_VALIDATE &&
           request->username_length > 0 &&
           request->username_length < AUTH_MAX_USER &&
           request->password_length > 0 &&
           request->password_length < AUTH_MAX_PASSWORD &&
           request->username[request->username_length] == '\0' &&
           strnlen(request->username, AUTH_MAX_USER) == request->username_length;
}

static int permanently_drop(uid_t uid, gid_t gid)
{
    if (setgroups(0, NULL) == -1 ||
        setresgid(gid, gid, gid) == -1 ||
        setresuid(uid, uid, uid) == -1)
        return -1;
    if (getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid) {
        errno = EPERM;
        return -1;
    }
    errno = 0;
    if (setuid(0) != -1 || errno != EPERM) {
        errno = EPERM;
        return -1;
    }
    fprintf(stderr, "Privilege check: uid=%ld euid=%ld gid=%ld egid=%ld; "
                    "root reacquisition rejected\n",
            (long)getuid(), (long)geteuid(), (long)getgid(), (long)getegid());
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 7) {
        fprintf(stderr, "Usage: %s SOCKET VERIFIER_FILE ALLOWED_UID DROP_UID DROP_GID USERNAME\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    if (geteuid() != 0) {
        fputs("Backend must start with effective UID 0 for this demonstration\n", stderr);
        return EXIT_FAILURE;
    }
    unsigned long allowed_value, drop_uid_value, drop_gid_value;
    if (parse_id(argv[3], &allowed_value) || parse_id(argv[4], &drop_uid_value) ||
        parse_id(argv[5], &drop_gid_value)) {
        fputs("Invalid numeric UID/GID\n", stderr);
        return EXIT_FAILURE;
    }

    char verifier[256] = {0};
    if (load_verifier(argv[2], argv[6], verifier, sizeof(verifier)) == -1) {
        perror("load verifier");
        return EXIT_FAILURE;
    }
    int listener = make_listener(argv[1], (uid_t)allowed_value);
    if (listener == -1) {
        perror("create UNIX socket");
        secure_zero(verifier, sizeof(verifier));
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Backend ready: pid=%ld euid=%ld\n",
            (long)getpid(), (long)geteuid());

    int client = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
    if (client == -1) {
        perror("accept");
        goto fail;
    }
    struct ucred peer;
    socklen_t peer_length = sizeof(peer);
    if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &peer_length) == -1 ||
        peer.uid != (uid_t)allowed_value) {
        fputs("Rejected: unauthorized peer credentials\n", stderr);
        close(client);
        goto fail;
    }

    struct auth_request request = {0};
    int memory_fd = -1;
    if (receive_request(client, &request, &memory_fd) == -1 ||
        !valid_request(&request) || strcmp(request.username, argv[6]) != 0) {
        fputs("Rejected: malformed or non-validation request\n", stderr);
        close(client);
        if (memory_fd != -1)
            close(memory_fd);
        goto fail;
    }
    struct stat memory_info;
    if (fstat(memory_fd, &memory_info) == -1 ||
        !S_ISREG(memory_info.st_mode) ||
        memory_info.st_size != AUTH_MAX_PASSWORD) {
        fputs("Rejected: unsafe shared-memory object\n", stderr);
        close(memory_fd);
        close(client);
        goto fail;
    }

    char *password = mmap(NULL, AUTH_MAX_PASSWORD, PROT_READ | PROT_WRITE,
                          MAP_SHARED, memory_fd, 0);
    if (password == MAP_FAILED)
        goto fail_client;
    (void)mlock(password, AUTH_MAX_PASSWORD);
    (void)madvise(password, AUTH_MAX_PASSWORD, MADV_DONTDUMP);

    int authenticated = 0;
    if (password[request.password_length] == '\0' &&
        strnlen(password, AUTH_MAX_PASSWORD) == request.password_length) {
        struct crypt_data crypt_state = {0};
        char *candidate = crypt_r(password, verifier, &crypt_state);
        authenticated = candidate != NULL &&
                        strlen(candidate) == strlen(verifier) &&
                        constant_time_equal(candidate, verifier, strlen(verifier));
        secure_zero(&crypt_state, sizeof(crypt_state));
    }

    secure_zero(password, AUTH_MAX_PASSWORD);
    (void)munlock(password, AUTH_MAX_PASSWORD);
    munmap(password, AUTH_MAX_PASSWORD);
    close(memory_fd);
    secure_zero(verifier, sizeof(verifier));

    /*
     * Remove the rendezvous name while still privileged.  The already accepted
     * connection remains usable, and no new client can race in after this point.
     */
    if (unlink(argv[1]) == -1) {
        perror("unlink socket before privilege drop");
        close(client);
        goto fail;
    }
    if (permanently_drop((uid_t)drop_uid_value, (gid_t)drop_gid_value) == -1) {
        perror("permanently drop privileges");
        close(client);
        goto fail;
    }
    struct auth_response response = {
        .magic = AUTH_MAGIC, .version = AUTH_VERSION,
        .authenticated = (uint16_t)authenticated
    };
    if (send(client, &response, sizeof(response), MSG_NOSIGNAL) !=
        (ssize_t)sizeof(response))
        perror("send response");
    close(client);
    close(listener);
    return authenticated ? EXIT_SUCCESS : 2;

fail_client:
    close(memory_fd);
    close(client);
fail:
    secure_zero(verifier, sizeof(verifier));
    close(listener);
    unlink(argv[1]);
    return EXIT_FAILURE;
}
