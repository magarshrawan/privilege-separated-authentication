#define _GNU_SOURCE
#include "Protocol.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>

static void secure_zero(void *p, size_t n)
{
    volatile unsigned char *v = p;
    while (n-- != 0)
        *v++ = 0;
}

static int read_password(char *buffer, size_t capacity)
{
    struct termios old_state, no_echo;
    int changed = 0;

    if (isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_state) == 0) {
        no_echo = old_state;
        no_echo.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &no_echo) == 0)
            changed = 1;
    }

    fputs("Password: ", stderr);
    fflush(stderr);
    if (fgets(buffer, (int)capacity, stdin) == NULL) {
        if (changed)
            (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_state);
        return -1;
    }
    if (changed) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_state);
        fputc('\n', stderr);
    }

    size_t length = strcspn(buffer, "\n");
    if (buffer[length] != '\n' && !feof(stdin)) {
        int c;
        while ((c = getchar()) != '\n' && c != EOF)
            ;
        errno = EOVERFLOW;
        return -1;
    }
    buffer[length] = '\0';
    return (int)length;
}

static int connect_socket(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd == -1)
        return -1;

    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (strlen(path) >= sizeof(address.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strcpy(address.sun_path, path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_request_with_fd(int socket_fd, const struct auth_request *request,
                                int password_fd)
{
    struct iovec io = { .iov_base = (void *)request, .iov_len = sizeof(*request) };
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr message = {
        .msg_iov = &io, .msg_iovlen = 1,
        .msg_control = control, .msg_controllen = sizeof(control)
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &password_fd, sizeof(password_fd));
    return sendmsg(socket_fd, &message, MSG_NOSIGNAL) == (ssize_t)sizeof(*request) ? 0 : -1;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s SOCKET_PATH USERNAME\n", argv[0]);
        return EXIT_FAILURE;
    }
    size_t username_length = strnlen(argv[2], AUTH_MAX_USER);
    if (username_length == 0 || username_length == AUTH_MAX_USER) {
        fputs("Invalid username length\n", stderr);
        return EXIT_FAILURE;
    }

    int password_fd = memfd_create("auth-password", MFD_CLOEXEC);
    if (password_fd == -1) {
        perror("create password memory");
        return EXIT_FAILURE;
    }
    if (ftruncate(password_fd, AUTH_MAX_PASSWORD) == -1) {
        perror("size password memory");
        close(password_fd);
        return EXIT_FAILURE;
    }
    char *password = mmap(NULL, AUTH_MAX_PASSWORD, PROT_READ | PROT_WRITE,
                          MAP_SHARED, password_fd, 0);
    if (password == MAP_FAILED) {
        perror("mmap");
        close(password_fd);
        return EXIT_FAILURE;
    }
    (void)mlock(password, AUTH_MAX_PASSWORD);
    (void)madvise(password, AUTH_MAX_PASSWORD, MADV_DONTDUMP);

    int password_length = read_password(password, AUTH_MAX_PASSWORD);
    if (password_length <= 0) {
        perror("read password");
        secure_zero(password, AUTH_MAX_PASSWORD);
        munmap(password, AUTH_MAX_PASSWORD);
        close(password_fd);
        return EXIT_FAILURE;
    }

    struct auth_request request = {
        .magic = AUTH_MAGIC, .version = AUTH_VERSION,
        .operation = AUTH_OP_VALIDATE,
        .username_length = (uint32_t)username_length,
        .password_length = (uint32_t)password_length
    };
    memcpy(request.username, argv[2], username_length);

    int socket_fd = connect_socket(argv[1]);
    if (socket_fd == -1 ||
        send_request_with_fd(socket_fd, &request, password_fd) == -1) {
        perror("send authentication request");
        secure_zero(password, AUTH_MAX_PASSWORD);
        munmap(password, AUTH_MAX_PASSWORD);
        close(password_fd);
        if (socket_fd != -1)
            close(socket_fd);
        return EXIT_FAILURE;
    }

    struct auth_response response;
    ssize_t received = recv(socket_fd, &response, sizeof(response), MSG_WAITALL);
    secure_zero(password, AUTH_MAX_PASSWORD);
    (void)munlock(password, AUTH_MAX_PASSWORD);
    munmap(password, AUTH_MAX_PASSWORD);
    close(password_fd);
    close(socket_fd);

    if (received != (ssize_t)sizeof(response) || response.magic != AUTH_MAGIC ||
        response.version != AUTH_VERSION) {
        fputs("Invalid response from backend\n", stderr);
        return EXIT_FAILURE;
    }
    puts(response.authenticated ? "Authentication successful" :
                                  "Authentication failed");
    return response.authenticated ? EXIT_SUCCESS : 2;
}
