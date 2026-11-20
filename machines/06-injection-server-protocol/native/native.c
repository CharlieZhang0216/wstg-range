/* WSTG-INJT-13: stack buffer overflow + format string injection.
 * Intentionally vulnerable. Compiled -fno-stack-protector -z execstack -no-pie.
 * Line protocol on TCP 9000:
 *   PING            -> PONG
 *   OVF <data>      -> strcpy into a 64-byte buffer adjacent to a canary
 *   FMT <data>      -> printf(data) with attacker-controlled format string
 * Demonstrates memory corruption + disclosure only (no weaponisation).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define CANARY 0xDEADBEEFCAFEBABEUL

struct frame {
    char buf[64];
    unsigned long canary;
    unsigned long pad;
    void (*fn)(void);
};

static void safe_fn(void) { }

static unsigned long g_canary;

static void do_overflow(char *in) {
    struct frame f;
    f.canary = CANARY;
    f.pad = 0;
    f.fn = safe_fn;
    strcpy(f.buf, in);                 /* VULNERABLE: unbounded copy */
    g_canary = f.canary;
    f.fn();                            /* overflow past the canary smashes fn -> SIGSEGV */
}

static void do_format(char *in) {
    int secret = 0;
    char *marker = "FMT_STRING_LEAK_MARKER";
    /* VULNERABLE: user-controlled format string. The program passes pointer
     * arguments, so positional %n/%s can write/read them (classic fmt bug). */
    printf(in, &secret, &secret, &secret, &secret, marker, marker, marker, marker);
    printf("\nsecret=%d\n", secret);
    fflush(stdout);
}

static void handle(int fd) {
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    alarm(10);
    FILE *f = fdopen(fd, "r");
    if (!f) _exit(0);
    char line[8192];
    if (!fgets(line, sizeof(line), f)) _exit(0);
    line[strcspn(line, "\r\n")] = 0;
    if (strncmp(line, "PING", 4) == 0) {
        printf("PONG\n");
    } else if (strncmp(line, "OVF ", 4) == 0) {
        do_overflow(line + 4);
        /* printed by the caller: a return-address smash crashes before this */
        printf("canary=0x%lx smashed=%d\n", g_canary, g_canary != CANARY);
        printf("OVF_DONE\n");
    } else if (strncmp(line, "FMT ", 4) == 0) {
        do_format(line + 4);
    } else {
        printf("ECHO %s\n", line);
    }
    fflush(stdout);
    _exit(0);
}

int main(void) {
    signal(SIGCHLD, SIG_IGN);
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(9000);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    listen(srv, 64);
    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0) continue;
        pid_t pid = fork();
        if (pid == 0) { close(srv); handle(fd); _exit(0); }
        close(fd);
    }
}