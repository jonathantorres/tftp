#include "tftp.h"

void sig_intr(int i);
void cmd_ascii();
void cmd_binary();
void cmd_connect();
void cmd_exit();
void cmd_get();
void cmd_help();
void cmd_mode();
void cmd_put();
void cmd_status();
void cmd_trace();
void cmd_verbose();
int my_getline(FILE *fp);
char *gettoken(char *token);
void checkend();
void docmd(char *cmdptr);
int binary(char *word, int n);
void striphost(char *fname, char *hname);
int err_cmd(char *str);
void mainloop(FILE *fp);
void do_get(char *remfname, char *locfname);
void do_put(char *remfname, char *locfname);
FILE *file_open(char *fname, char *mode, int initblknum);
void file_close(FILE *fp);
int file_read(FILE *fp, char *ptr, int maxnbytes, int mode);
void file_write(FILE *fp, char *ptr, int nbytes, int mode);
int net_open(char *host, char *service, int port);
void net_close();
void t_start();
void t_stop();
int recv_RQERR(char *ptr, int nbytes);
void send_ERROR(int ecode, char *string);
void send_RQ(int opcode, char *fname, int mode);
void send_DATA(int blocknum, int nbytes);
void send_ACK(int blocknum);
void recv_xRQ(int opcode, char *ptr, int nbytes);
int fsm_loop(int opcode);
char *host_err_str();
int tcp_open(char *host, char *service, int port);
void net_send(char *buff, int len);
int net_recv(char *buff, int maxlen);
int recv_RRQ(char *ptr, int nbytes);
int recv_WRQ(char *ptr, int nbytes);
int recv_DATA(char *ptr, int nbytes);
int recv_ACK(char *ptr, int nbytes);
void strlccpy(char *dest, char *src);

/* keep in alphabetical order for binary search */
Cmds commands[] = {
    { "?",       cmd_help, },
    { "ascii",   cmd_ascii, },
    { "binary",  cmd_binary, },
    { "connect", cmd_connect, },
    { "exit",    cmd_exit, },
    { "get",     cmd_get, },
    { "help",    cmd_help, },
    { "mode",    cmd_mode, },
    { "put",     cmd_put, },
    { "quit",    cmd_exit, },
    { "status",  cmd_status, },
    { "trace",   cmd_trace, },
    { "verbose", cmd_verbose, },
};

int fsm_error(void);
int fsm_invalid(void);

/*
 * Finite state machine table.
 * This is just a 2-d array indexed by the last opcode sent and
 * the opcode just received.  The result is the address of a
 * function to call to process the received opcode.
 */
int (*fsm_ptr [ OP_MAX + 1 ] [ OP_MAX + 1 ] ) () = {
    {
        fsm_invalid,    /* [sent = 0]        [recv = 0]             */
        recv_RRQ,       /* [sent = 0]        [recv = OP_RRQ]        */
        recv_WRQ,       /* [sent = 0]        [recv = OP_WRQ]        */
        fsm_invalid,    /* [sent = 0]        [recv = OP_DATA]       */
        fsm_invalid,    /* [sent = 0]        [recv = OP_ACK]        */
        fsm_invalid,    /* [sent = 0]        [recv = OP_ERROR]      */
    },

    {
        fsm_invalid,    /* [sent = OP_RRQ]   [recv = 0]             */
        fsm_invalid,    /* [sent = OP_RRQ]   [recv = OP_RRQ]        */
        fsm_invalid,    /* [sent = OP_RRQ]   [recv = OP_WRQ]        */
        fsm_invalid,    /* [sent = OP_RRQ]   [recv = OP_DATA]       */
        fsm_invalid,    /* [sent = OP_RRQ]   [recv = OP_ACK]        */
        fsm_invalid,    /* [sent = OP_RRQ]   [recv = OP_ERROR]      */
    },

    {
        fsm_invalid,    /* [sent = OP_WRQ]   [recv = 0]             */
        fsm_invalid,    /* [sent = OP_WRQ]   [recv = OP_RRQ]        */
        fsm_invalid,    /* [sent = OP_WRQ]   [recv = OP_WRQ]        */
        fsm_invalid,    /* [sent = OP_WRQ]   [recv = OP_DATA]       */
        fsm_invalid,    /* [sent = OP_WRQ]   [recv = OP_ACK]        */
        fsm_invalid,    /* [sent = OP_WRQ]   [recv = OP_ERROR]      */
    },

    {
        fsm_invalid,    /* [sent = OP_DATA]  [recv = 0]             */
        fsm_invalid,    /* [sent = OP_DATA]  [recv = OP_RRQ]        */
        fsm_invalid,    /* [sent = OP_DATA]  [recv = OP_WRQ]        */
        fsm_invalid,    /* [sent = OP_DATA]  [recv = OP_DATA]       */
        recv_ACK,       /* [sent = OP_DATA]  [recv = OP_ACK]        */
        fsm_error,      /* [sent = OP_DATA]  [recv = OP_ERROR]      */
    },

    {
        fsm_invalid,    /* [sent = OP_ACK]   [recv = 0]             */
        fsm_invalid,    /* [sent = OP_ACK]   [recv = OP_RRQ]        */
        fsm_invalid,    /* [sent = OP_ACK]   [recv = OP_WRQ]        */
        recv_DATA,      /* [sent = OP_ACK]   [recv = OP_DATA]       */
        fsm_invalid,    /* [sent = OP_ACK]   [recv = OP_ACK]        */
        fsm_error,      /* [sent = OP_ACK]   [recv = OP_ERROR]      */
    },

    {
        fsm_invalid,    /* [sent = OP_ERROR] [recv = 0]             */
        fsm_invalid,    /* [sent = OP_ERROR] [recv = OP_RRQ]        */
        fsm_invalid,    /* [sent = OP_ERROR] [recv = OP_WRQ]        */
        fsm_invalid,    /* [sent = OP_ERROR] [recv = OP_DATA]       */
        fsm_invalid,    /* [sent = OP_ERROR] [recv = OP_ACK]        */
        fsm_error       /* [sent = OP_ERROR] [recv = OP_ERROR]      */
    }
};

#define NCMDS (sizeof(commands) / sizeof(Cmds))

int ncmds = NCMDS;

static char line[MAXLINE] = { 0 };
static char *lineptr = NULL;

static struct timeval time_start, time_stop; /* for real time */
static struct rusage ru_start, ru_stop;      /* for user & sys time */
static double start, stop, seconds;

struct sockaddr_in tcp_srv_addr;   /* server's Internet socket addr */
struct servent     tcp_serv_info;  /* from getservbyname() */
struct hostent     tcp_host_info;  /* from gethostbyname() */

int h_errno;       /* host error number */
int h_nerr;        /* # of error message strings */
char *h_errlist[]; /* the error message table */

static int lastcr   = 0;   /* 1 if last character was a carriage-return */
static int nextchar = 0;

int main(int argc, char *argv[])
{
    int i = 0;
    char *s = NULL;
    FILE *fp = NULL;

    pname = argv[0];

    while (--argc > 0 && (*++argv)[0] == '-') {
        for (s = argv[0]+1; *s != '\0'; s++) {
            switch (*s) {
                case 'h':
                    if (--argc <= 0) {
                       puts("-h requires another argument");
                       exit(EXIT_FAILURE);
                    }
                    strcpy(hostname, *++argv);
                    break;
                case 't':
                    traceflag = 1;
                    break;
                case 'v':
                    verboseflag = 1;
                    break;
                default:
                    fprintf(stderr, "unknown command line option: %c\n", *s);
                    exit(EXIT_FAILURE);
            }
        }
    }

    fp = stdin;
    do {
        if (argc > 0 && (fp = fopen(argv[i], "r")) == NULL) {
            fprintf(stderr, "%s: can't open %s for reading\n", pname, argv[i]);
        }
        mainloop(fp);
    } while (++i < argc);

    exit(EXIT_SUCCESS);

    return 0;
}

void mainloop(FILE *fp)
{
    if (signal(SIGINT, SIG_IGN) != SIG_IGN) {
        signal(SIGINT, sig_intr);
    }

    /*
     * Main loop. Read a command and execute it.
     * This loop is terminated by a "quit" command, or an
     * end-of-file on the command stream.
     */
    if (setjmp(jmp_mainloop) < 0) {
        puts("Timeout");
        return;
    }

    if (interactive) {
        printf("%s", prompt);
    }

    while (my_getline(fp)) {
        if (gettoken(command) != NULL) {
            docmd(command);
        }

        if (interactive) {
            printf("%s", prompt);
        }
    }
}

void sig_intr(int i)
{
    if (i) {}
    signal(SIGALRM, SIG_IGN);
    alarm(0);

    longjmp(jmp_mainloop, 1);
}

void cmd_ascii()
{
    modetype = MODE_ASCII;
}

void cmd_binary()
{
    modetype = MODE_BINARY;
}

void cmd_connect()
{
    int val;

    if (gettoken(hostname) == NULL) {
        err_cmd("missing hostname");
    }

    if (gettoken(temptoken) == NULL) {
        return;
    }

    val = atoi(temptoken);
    if (val < 0) {
        err_cmd("invalid port number");
    }
    port = val;
}

void cmd_exit()
{
    exit(EXIT_SUCCESS);
}

void cmd_get()
{
    char remfname[MAXFILENAME], locfname[MAXFILENAME];
    char *index();

    if (gettoken(remfname) == NULL) {
        err_cmd("the remote filename must be specified");
    }
    if (gettoken(locfname) == NULL) {
        err_cmd("the local filename must be specified");
    }

    if (index(locfname, ':') != NULL) {
        err_cmd("can't have 'host:' in local filename");
    }

    striphost(remfname, hostname);
    if (hostname[0] == 0) {
        err_cmd("no host has been specified");
    }

    do_get(remfname, locfname);
}

void cmd_help()
{
    for (int i = 0; i < ncmds; i++) {
        printf("  %s\n", commands[i].cmd_name);
    }
}

void cmd_mode()
{
    if (gettoken(temptoken) == NULL) {
        err_cmd("a mode type must be specified");
    } else {
        if (strcmp(temptoken, "ascii") == 0) {
            modetype = MODE_ASCII;
        } else if (strcmp(temptoken, "binary") == 0) {
            modetype = MODE_BINARY;
        } else {
            err_cmd("mode must be 'ascii' or 'binary'");
        }
    }
}

void cmd_put()
{
    char remfname[MAXFILENAME];
    char locfname[MAXFILENAME];

    if (gettoken(locfname) == NULL) {
        err_cmd("the local filename must be specified");
    }

    if (gettoken(remfname) == NULL) {
        err_cmd("the remote filename must be specified");
    }

    if (index(locfname, ':') != NULL) {
        err_cmd("can't have 'host:' in local filename");
    }

    striphost(remfname, hostname);

    if (hostname[0] == 0) {
        err_cmd("no host has been specified");
    }

    do_put(remfname, locfname);
}

void cmd_status()
{
    if (connected) {
        printf("Connected\n");
    } else {
        printf("Not connected\n");
    }

    printf("mode = ");
    switch (modetype) {
        case MODE_ASCII:
            printf("netascii");
            break;
        case MODE_BINARY:
            printf("octet (binary)");
            break;
        default:
            puts("unknown modetype");
    }

    printf(", verbose = %s", verboseflag ? "on" : "off");
    printf(", trace = %s\n", traceflag ? "on" : "off");
}

void cmd_trace()
{
    traceflag = !traceflag;
}

void cmd_verbose()
{
    verboseflag = !verboseflag;
}

int my_getline(FILE *fp)
{
    if (fgets(line, MAXLINE, fp) == NULL) {
        return 0;
    }
    lineptr = line;

    return 1;
}

char *gettoken(char *token)
{
    int c;
    char *tokenptr;

    while ((c = *lineptr++) == ' ' || c == '\t') {
        ;       /* skip leading white space */
    }

    if (c == '\0' || c == '\n') {
        return NULL;
    }

    tokenptr = token;
    *tokenptr++ = c;

    /*
     * Now collect everything up to the next space, tab, newline, or null.
     */
    while ((c = *lineptr++) != ' ' && c != '\t' && c != '\n' && c != '\0') {
        *tokenptr++ = c;
    }

    /* null terminate token */
    *tokenptr = 0;
    return(token);
}

void checkend()
{
    if (gettoken(temptoken) != NULL) {
        err_cmd("trailing garbage");
    }
}

void docmd(char *cmdptr)
{
    int i;

    if ((i = binary(cmdptr, ncmds)) < 0) {
        err_cmd(cmdptr);
    }

    (*commands[i].cmd_func)();

    checkend();
}

int binary(char *word, int n)
{
    int low, high, mid, cond;

    low  = 0;
    high = n - 1;
    while (low <= high) {
        mid = (low + high) / 2;
        if ((cond = strcmp(word, commands[mid].cmd_name)) < 0) {
            high = mid - 1;
        } else if (cond > 0) {
            low = mid + 1;
        } else {
            return mid;    /* found it, return index in array */
        }
    }
    return -1; /* not found */
}

void striphost(char *fname, char *hname)
{
    char *index();
    char *ptr1, *ptr2;

    if ((ptr1 = index(fname, ':')) == NULL) {
        return;     /* there is not a "host:" present */
    }

    /*
     * Copy the entire "host:file" into the hname array,
     * then replace the colon with a null byte.
     */
    strcpy(hname, fname);
    ptr2 = index(hname, ':');
    *ptr2 = 0; /* null terminates the "host" string */

    /*
     * Now move the "file" string left in the fname array,
     * removing the "host:" portion.
     */
    strcpy(fname, ptr1 + 1);    /* ptr1 + 1 to skip over the ':' */
}

int err_cmd(char *str)
{
    fprintf(stderr, "%s: '%s' command error", pname, command);
    if (strlen(str) > 0) {
        fprintf(stderr, ": %s", str);
    }

    fprintf(stderr, "\n");
    fflush(stderr);

    longjmp(jmp_mainloop, 1);   /* 1 -> not a timeout, we've already
                                    printed our error message */
}

void do_get(char *remfname, char *locfname)
{
    if ((localfp = file_open(locfname, "w", 1)) == NULL) {
        fprintf(stderr, "can't fopen %s for writing\n", locfname);
        return;
    }

    if (net_open(hostname, TFTP_SERVICE, port) < 0) {
        return;
    }

    totnbytes = 0;

    t_start();      /* start timer for statistics */
    send_RQ(OP_RRQ, remfname, modetype);
    fsm_loop(OP_RRQ);
    t_stop();       /* stop timer for statistics */

    net_close();
    file_close(localfp);
    printf("Received %ld bytes in %.1f seconds\n", totnbytes, t_getrtime());
                /* print stastics */
}

void do_put(char *remfname, char *locfname)
{
    if ((localfp = file_open(locfname, "r", 0)) == NULL) {
        fprintf(stderr, "can't fopen %s for reading\n", locfname);
        return;
    }

    if (net_open(hostname, TFTP_SERVICE, port) < 0) {
        return;
    }

    totnbytes = 0;
    t_start();

    lastsend = MAXDATA;
    send_RQ(OP_WRQ, remfname, modetype);
    fsm_loop(OP_WRQ);
    t_stop();       /* stop timer for statistics */
    net_close();

    file_close(localfp);

    printf("Sent %ld bytes in %.1f seconds\n", totnbytes, t_getrtime());
                /* print stastics */
}

/*
 * Open the local file for reading or writing.
 * Return a FILE pointer, or NULL on error.
 */
FILE *file_open(char *fname, char *mode, int initblknum)
{
    FILE *fp;

    if (strcmp(fname, "-") == 0) {
        fp = stdout;
    } else if ((fp = fopen(fname, mode)) == NULL) {
        return ((FILE *) 0);
    }

    nextblknum = initblknum; /* for first data packet or first ACK */
    lastcr     = 0;          /* for file_write() */
    nextchar   = -1;         /* for file_read() */

    DEBUG2("file_open: opened %s, mode = %s", fname, mode);

    return fp;
}

/*
 * Close the local file.
 * This causes the standard i/o system to flush its buffers for this file.
 */
void file_close(FILE *fp)
{
    if (lastcr) {
        fprintf(stderr, "final character was a CR\n");
    }
    if (nextchar >= 0) {
        fprintf(stderr, "nextchar >= 0\n");
    }

    if (fp == stdout) {
        return;     /* don't close standard output */
    } else if (fclose(fp) == EOF) {
        fprintf(stderr, "fclose error\n");
    }
}

void net_close()
{
    DEBUG2("net_close: host = %s, fd = %d", openhost, sockfd);
    close(sockfd);
    sockfd = -1;
}

int net_open(char *host, char *service, int port)
{
    if ((sockfd = tcp_open(host, service, port)) < 0) {
        return -1;
    }

    DEBUG2("net_open: host %s, port# %d",
            inet_ntoa(tcp_srv_addr.sin_addr),
            ntohs(tcp_srv_addr.sin_port));

    strcpy(openhost, host);     /* save the host's name */

    return 0;
}

void t_start()
{
    if (gettimeofday(&time_start, (struct timezone *) 0) < 0) {
        perror("t_start: gettimeofday() error");
    }

    if (getrusage(RUSAGE_SELF, &ru_start) < 0) {
        perror("t_start: getrusage() error");
    }
}

void t_stop()
{
    if (getrusage(RUSAGE_SELF, &ru_stop) < 0) {
        perror("t_stop: getrusage() error");
    }

    if (gettimeofday(&time_stop, (struct timezone *) 0) < 0) {
        perror("t_stop: gettimeofday() error");
    }
}

void send_RQ(int opcode, char *fname, int mode)
{
    int len;
    char *modestr;

    DEBUG2("sending RRQ/WRQ for %s, mode = %d", fname, mode);

    stshort(opcode, sendbuff);
    strcpy(sendbuff+2, fname);

    len = 2 + strlen(fname) + 1;    /* +1 for null byte at end of fname */

    switch(mode) {
        case MODE_ASCII:
            modestr = "netascii";
            break;
        case MODE_BINARY:
            modestr = "octet";
            break;
        default:
            puts("unknown mode");
    }

    strcpy(sendbuff + len, modestr);
    len += strlen(modestr) + 1; /* +1 for null byte at end of modestr */

    sendlen = len;
    net_send(sendbuff, sendlen);
    op_sent = opcode;
}

int recv_RQERR(char *ptr, int nbytes)
{
    int ecode;

    ecode = ldshort(ptr);
    ptr += 2;
    nbytes -= 2;
    ptr[nbytes] = 0;    /* assure it's null terminated ... */

    DEBUG2("ERROR received, %d bytes, error code %d", nbytes, ecode);

    fflush(stdout);
    fprintf(stderr, "Error# %d: %s\n", ecode, ptr);
    fflush(stderr);

    return -1; /* terminate finite state loop */
}

int fsm_loop(int opcode)
{
    int nbytes;
    op_sent = opcode;

    while (true) {
        if ((nbytes = net_recv(recvbuff, MAXBUFF)) < 0) {
            perror("net_recv error");
            exit(EXIT_FAILURE);
        }

        if (nbytes < 4) {
            fprintf(stderr, "receive length = %d bytes\n", nbytes);
        }

        op_recv = ldshort(recvbuff);

        if (op_recv < OP_MIN || op_recv > OP_MAX) {
            fprintf(stderr, "invalid opcode received: %d\n", op_recv);
        }

        /*
         * We call the appropriate function, passing the address
         * of the receive buffer and its length.  These arguments
         * ignore the received-opcode, which we've already processed.
         *
         * We assume the called function will send a response to the
         * other side.  It is the called function's responsibility to
         * set op_sent to the op-code that it sends to the other side.
         */
        if ((*fsm_ptr[op_sent][op_recv])(recvbuff + 2, nbytes - 2) < 0){
            /*
             * When the called function returns -1, this loop
             * is done.  Turn off the signal handler for
             * timeouts and return to the caller.
             */
            signal(SIGALRM, SIG_DFL);
            return 0;
        }
    }

    return 0;
}

int tcp_open(char *host, char *service, int port)
{
    int fd, resvport;
    unsigned long inaddr;
    char *host_err_str();
    struct servent *sp;
    struct hostent *hp;

    /*
     * Initialize the server's Internet address structure.
     * We'll store the actual 4-byte Internet address and the
     * 2-byte port# below.
     */
    memset((char *) &tcp_srv_addr, 0, sizeof(tcp_srv_addr));
    tcp_srv_addr.sin_family = AF_INET;

    if (service != NULL) {
        if ((sp = getservbyname(service, "tcp")) == NULL) {
            fprintf(stderr, "tcp_open: unknown service: %s/tcp\n", service);
            return -1;
        }
        tcp_serv_info = *sp;            /* structure copy */
        if (port > 0) {
            tcp_srv_addr.sin_port = htons(port);
        } else {
            tcp_srv_addr.sin_port = sp->s_port;
        }
    } else {
        if (port <= 0) {
            fprintf(stderr, "tcp_open: must specify either service or port\n");
            return -1;
        }
        tcp_srv_addr.sin_port = htons(port);
    }

    if ((inaddr = inet_addr(host)) != INADDR_NONE) {
        memcpy((char *) &tcp_srv_addr.sin_addr, (char *) &inaddr, sizeof(inaddr));
        tcp_host_info.h_name = NULL;
    } else {
        if ((hp = gethostbyname(host)) == NULL) {
            fprintf(stderr, "tcp_open: host name error: %s %s",
                        host, host_err_str());
            return -1;
        }

        tcp_host_info = *hp;    /* found it by name, structure copy */
        bcopy((char *) &tcp_srv_addr.sin_addr, hp->h_addr, hp->h_length);
    }

    if (port >= 0) {
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            fprintf(stderr, "tcp_open: can't create TCP socket");
            return -1;
        }
    } else if (port < 0) {
        resvport = IPPORT_RESERVED - 1;
        if ((fd = rresvport(&resvport)) < 0) {
            fprintf(stderr, "tcp_open: can't get a reserved TCP port");
            return -1;
        }
    }

    if (connect(fd, (struct sockaddr *) &tcp_srv_addr, sizeof(tcp_srv_addr)) < 0) {
        perror("tcp_open: can't connect to server");
        close(fd);
        return -1;
    }

    return(fd); /* all OK */
}

char *host_err_str()
{
    static char msgstr[200];

    if (h_errno != 0) {
        if (h_errno > 0 && h_errno < h_nerr) {
            sprintf(msgstr, "(%s)", h_errlist[h_errno]);
        } else {
            sprintf(msgstr, "(h_errno = %d)", h_errno);
        }
    } else {
        msgstr[0] = '\0';
    }

    return msgstr;
}

void net_send(char *buff, int len)
{
    int   rc;
    short templen;

    DEBUG1("net_send: sent %d bytes", len);

    templen = htons(len);
    rc = writen(sockfd, (char *) &templen, sizeof(short));
    if (rc != sizeof(short)) {
        fprintf(stderr, "writen error of length prefix\n");
    }

    rc = writen(sockfd, buff, len);
    if (rc != len) {
        fprintf(stderr, "writen error\n");
    }
}

int net_recv(char *buff, int maxlen)
{
    int   nbytes;
    short templen;    /* value-result parameter */

again1:
    if ((nbytes = readn(sockfd, (char *) &templen, sizeof(short))) < 0) {
        if (errno == EINTR) {
            errno = 0;      /* assume SIGCLD */
            goto again1;
        }
        perror("readn error for length prefix");
        exit(EXIT_FAILURE);
    }
    if (nbytes != sizeof(short)) {
        fprintf(stderr, "error in readn of length prefix\n");
    }

    templen = ntohs(templen);       /* #bytes that follow */
    if (templen > maxlen) {
        fprintf(stderr, "record length too large\n");
    }

again2:
    if ((nbytes = readn(sockfd, buff, templen)) < 0) {
        if (errno == EINTR) {
            errno = 0;      /* assume SIGCLD */
            goto again2;
        }
        perror("readn error");
        exit(EXIT_FAILURE);
    }
    if (nbytes != templen) {
        fprintf(stderr, "error in readn\n");
    }

    DEBUG1("net_recv: got %d bytes", nbytes);

    return nbytes;     /* return the actual length of the message */
}

int fsm_error(void)
{
    fprintf(stderr, "error received: op_sent = %d, op_recv = %d\n",
            op_sent, op_recv);

    return 0;
}

/*
 * Invalid state transition.  Something is wrong.
 */
int fsm_invalid(void)
{
    fprintf(stderr, "protocol botch: op_sent = %d, op_recv = %d\n",
            op_sent, op_recv);

    return 0;
}

/*
 * Data packet received.  Send an acknowledgment.
 * Called by finite state machine.
 * Note that this function is called for both the client and the server.
 */
int recv_DATA(char *ptr, int nbytes)
{
    int recvblknum;

    recvblknum = ldshort(ptr);
    ptr += 2;
    nbytes -= 2;

    DEBUG2("DATA received, %d bytes, block# %d", nbytes, recvblknum);

    if (nbytes > MAXDATA) {
        fprintf(stderr, "data packet received with length = %d bytes\n", nbytes);
    }

    if (recvblknum == nextblknum) {
        /*
         * The data packet is the expected one.
         * Increment our expected-block# for the next packet.
         */
        nextblknum++;
        totnbytes += nbytes;

        if (nbytes > 0) {
            /*
             * Note that the final data packet can have a
             * data length of zero, so we only write the
             * data to the local file if there is data.
             */
            file_write(localfp, ptr, nbytes, modetype);
        }

        /*
         * If the length of the data is between 0-511, this is
         * the last data block.  For the server, here's where
         * we have to close the file.  For the client, the
         * "get" command processing will close the file.
         */
        if (nbytes < MAXDATA) {
            file_close(localfp);
        }
    } else if (recvblknum < (nextblknum - 1)) {
        /*
         * We've just received data block# N (or earlier, such as N-1,
         * N-2, etc.) from the other end, but we were expecting data
         * block# N+2.  But if we were expecting N+2 it means we've
         * already received N+1, so the other end went backwards from
         * N+1 to N (or earlier).  Something is wrong.
         */

        fprintf(stderr, "recvblknum < nextblknum - 1\n");
    } else if (recvblknum > nextblknum) {
        /*
         * We've just received data block# N (or later, such as N+1,
         * N+2, etc.) from the other end, but we were expecting data
         * block# N-1.  But this implies that the other end has
         * received an ACK for block# N-1 from us.  Something is wrong.
         */
        fprintf(stderr, "recvblknum > nextblknum\n");
    }

    /*
     * The only case not handled above is "recvblknum == (nextblknum - 1)".
     * This means the other end never saw our ACK for the last data
     * packet and retransmitted it.  We just ignore the retransmission
     * and send another ACK.
     *
     * Acknowledge the data packet.
     */
    send_ACK(recvblknum);

    /*
     * If the length of the data is between 0-511, we've just
     * received the final data packet, else there is more to come.
     */
    return (nbytes == MAXDATA) ? 0 : -1;
}

/*
 * ACK packet received.  Send some more data.
 * Called by finite state machine.  Also called by recv_RRQ() to
 * start the transmission of a file to the client.
 * Note that this function is called for both the client and the server.
 */
int recv_ACK(char *ptr, int nbytes)
{
    int recvblknum;

    recvblknum = ldshort(ptr);
    if (nbytes != 2) {
        fprintf(stderr, "ACK packet received with length = %d bytes\n", nbytes + 2);
    }

    DEBUG1("ACK received, block# %d", recvblknum);

    if (recvblknum == nextblknum) {
        /*
         * The received acknowledgment is for the expected data
         * packet that we sent.
         * Fill the transmit buffer with the next block of data
         * to send.
         * If there's no more data to send, then we might be
         * finished.  Note that we must send a final data packet
         * containing 0-511 bytes of data.  If the length of the
         * last packet that we sent was exactly 512 bytes, then we
         * must send a 0-length data packet.
         */
        if ((nbytes = file_read(localfp, sendbuff + 4,
                        MAXDATA, modetype)) == 0) {
            if (lastsend < MAXDATA) {
                return -1; /* done */
            }
            /* else we'll send nbytes=0 of data */
        }

        lastsend = nbytes;
        nextblknum++;       /* incr for this new packet of data */
        totnbytes += nbytes;
        send_DATA(nextblknum, nbytes);

        return 0;

    } else if (recvblknum < (nextblknum - 1)) {
        /*
         * We've just received the ACK for block# N (or earlier, such
         * as N-1, N-2, etc) from the other end, but we were expecting
         * the ACK for block# N+2.  But if we're expecting the ACK for
         * N+2 it means we've already received the ACK for N+1, so the
         * other end went backwards from N+1 to N (or earlier).
         * Something is wrong.
         */
        fprintf(stderr, "recvblknum < nextblknum - 1\n");

    } else if (recvblknum > nextblknum) {
        /*
         * We've just received the ACK for block# N (or later, such
         * as N+1, N+2, etc) from the other end, but we were expecting
         * the ACK for block# N-1.  But this implies that the other
         * end has already received data block# N-1 from us.
         * Something is wrong.
         */
        fprintf(stderr, "recvblknum > nextblknum\n");

    }

    /*
     * Here we have "recvblknum == (nextblknum - 1)".
     * This means we received a duplicate ACK.  This means either:
     * (1) the other side never received our last data packet;
     * (2) the other side's ACK got delayed somehow.
     *
     * If we were to retransmit the last data packet, we would start
     * the "Sorcerer's Apprentice Syndrome."  We'll just ignore this
     * duplicate ACK, returning to the FSM loop, which will initiate
     * another receive.
     */
    return 0;
}


/*
 * RRQ packet received.
 * Called by the finite state machine.
 * This (and receiving a WRQ) are the only ways the server gets started.
 */
int recv_RRQ(char *ptr, int nbytes)
{
    char ackbuff[2];

    recv_xRQ(OP_RRQ, ptr, nbytes);  /* verify the RRQ packet */

    /*
     * Set things up so we can just call recv_ACK() and pretend we
     * received an ACK, so it'll send the first data block to the
     * client.
     */
    lastsend = MAXDATA;
    stshort(0, ackbuff);    /* pretend its an ACK of block# 0 */

    recv_ACK(ackbuff, 2);   /* this sends data block# 1 */

    return 0;  /* the finite state machine takes over from here */
}

/*
 * WRQ packet received.
 * Called by the finite state machine.
 * This (and receiving an RRQ) are the only ways the server gets started.
 */
int recv_WRQ(char *ptr, int nbytes)
{
    recv_xRQ(OP_WRQ, ptr, nbytes);  /* verify the WRQ packet */

    /*
     * Call send_ACK() to acknowledge block# 0, which will cause
     * the client to send data block# 1.
     */
    nextblknum = 1;
    send_ACK(0);

    return 0;  /* the finite stat machine takes over from here */
}
/*
 * Write data to the local file.
 * Here is where we handle any conversion between the mode of the
 * file on the network and the local system's conventions.
 */
void file_write(FILE *fp, char *ptr, int nbytes, int mode)
{
    int c, i;

    if (mode == MODE_BINARY) {
        /*
         * For binary mode files, no conversion is required.
         */
        i = write(fileno(fp), ptr, nbytes);
        if (i != nbytes) {
            fprintf(stderr, "write error to local file, i = %d\n", i);
        }
    } else if (mode == MODE_ASCII) {
        /*
         * For files that are transferred in netascii, we must
         * perform the following conversions:
         *
         *  CR,LF             ->  newline = '\n'
         *  CR,NULL           ->  CR      = '\r'
         *  CR,anything_else  ->  undefined (we don't allow this)
         *
         * Note that we have to use the global "lastcr" to remember
         * if the last character was a carriage-return or not,
         * since if the last character of a buffer is a CR, we have
         * to remember that when we're called for the next buffer.
         */
        for (i = 0; i < nbytes; i++) {
            c = *ptr++;
            if (lastcr) {
                if (c == '\n') {
                    c = '\n';
                } else if (c == '\0') {
                    c = '\r';
                } else {
                    fprintf(stderr, "CR followed by 0x%02x\n", c);
                }
                lastcr = 0;
            } else if (c == '\r') {
                lastcr = 1;
                continue;   /* get next character */
            }

            if (putc(c, fp) == EOF) {
                fprintf(stderr, "write error from putc to local file\n");
            }
        }
    } else {
        fprintf(stderr, "unknown MODE value\n");
    }
}


/*
 * Read data from the local file.
 * Here is where we handle any conversion between the file's mode
 * on the local system and the network mode.
 *
 * Return the number of bytes read (between 1 and maxnbytes, inclusive)
 * or 0 on EOF.
 */
int file_read(FILE *fp, char *ptr, int maxnbytes, int mode)
{
    int c;
    int count = 0;

    if (mode == MODE_BINARY) {
        count = read(fileno(fp), ptr, maxnbytes);
        if (count < 0) {
            perror("read error on local file");
            exit(EXIT_FAILURE);
        }

        return count;      /* will be 0 on EOF */
    } else if (mode == MODE_ASCII) {
        /*
         * For files that are transferred in netascii, we must
         * perform the reverse conversions that file_write() does.
         * Note that we have to use the global "nextchar" to
         * remember if the next character to output is a linefeed
         * or a null, since the second byte of a 2-byte sequence
         * may not fit in the current buffer, and may have to go
         * as the first byte of the next buffer (i.e., we have to
         * remember this fact from one call to the next).
         */
        for (count = 0; count < maxnbytes; count++) {
            if (nextchar >= 0) {
                *ptr++ = nextchar;
                nextchar = -1;
                continue;
            }

            c = getc(fp);

            if (c == EOF) { /* EOF return means eof or error */
                if (ferror(fp)) {
                   fprintf(stderr, "read err from getc on local file\n");
                }
                return count;
            } else if (c == '\n') {
                c = '\r';       /* newline -> CR,LF */
                nextchar = '\n';
            } else if (c == '\r') {
                nextchar = '\0';    /* CR -> CR,NULL */
            } else {
                nextchar = -1;
            }

            *ptr++ = c;
        }

        return count;
    } else {
        fprintf(stderr, "unknown MODE value\n");
    }

    return count;
}

/*
 * Send an acknowledgment packet to the other system.
 * Called by the recv_DATA() function below and also called by
 * recv_WRQ().
 */
void send_ACK(int blocknum)
{
    DEBUG1("sending ACK for block# %d", blocknum);

    stshort(OP_ACK, sendbuff);
    stshort(blocknum, sendbuff + 2);

    sendlen = 4;
    net_send(sendbuff, sendlen);

#ifdef  SORCERER
    /*
     * If you want to see the Sorcerer's Apprentice syndrome,
     * #define SORCERER, then run this program as the client and
     * get a file from a server that doesn't have the bug fixed
     * (such as the 4.3BSD version).
     * Turn on the trace option, and you'll see the duplicate
     * data packets sent by the broken server, starting with
     * block# 2.  Yet when the transfer is complete, you'll find
     * the file was received correctly.
     */

    if (blocknum == 1) {
        net_send(sendbuff, sendlen);    /* send the first ACK twice */
    }
#endif

    op_sent = OP_ACK;
}

/*
 * Send data to the other system.
 * The data must be stored in the "sendbuff" by the caller.
 * Called by the recv_ACK() function below.
 */
void send_DATA(int blocknum, int nbytes)
{
    DEBUG2("sending %d bytes of DATA with block# %d", nbytes, blocknum);

    stshort(OP_DATA, sendbuff);
    stshort(blocknum, sendbuff + 2);

    sendlen = nbytes + 4;
    net_send(sendbuff, sendlen);
    op_sent = OP_DATA;
}


/*
 * Process an RRQ or WRQ that has been received.
 * Called by the 2 routines above.
 */
void recv_xRQ(int opcode, char *ptr, int nbytes)
{
    int  i;
    char *saveptr;
    char filename[MAXFILENAME], dirname[MAXFILENAME], mode[MAXFILENAME];
    struct stat statbuff;

    /*
     * Assure the filename and mode are present and
     * null-terminated.
     */
    saveptr = ptr;      /* points to beginning of filename */
    for (i = 0; i < nbytes; i++) {
        if (*ptr++ == '\0') {
            goto FileOK;
        }
    }
    fprintf(stderr, "Invalid filename\n");

FileOK:
    strcpy(filename, saveptr);
    saveptr = ptr;      /* points to beginning of Mode */

    for ( ; i < nbytes; i++) {
        if (*ptr++ == '\0') {
            goto ModeOK;
        }
    }
    fprintf(stderr, "Invalid Mode\n");

ModeOK:
    strlccpy(mode, saveptr);    /* copy and convert to lower case */

    if (strcmp(mode, "netascii") == 0) {
        modetype = MODE_ASCII;
    } else if (strcmp(mode, "octet") == 0) {
        modetype = MODE_BINARY;
    } else {
        send_ERROR(ERR_BADOP, "Mode isn't netascii or octet");
    }

    /*
     * Validate the filename.
     * Note that as a daemon we might be running with root
     * privileges.  Since there are no user-access checks with
     * tftp (as compared to ftp, for example) we will only
     * allow access to files that are publicly accessible.
     *
     * Also, since we're running as a daemon, our home directory
     * is the root, so any filename must have it's full
     * pathname specified (i.e., it must begin with a slash).
     */
    if (filename[0] != '/') {
        send_ERROR(ERR_ACCESS, "filename must begin with '/'");
    }

    if (opcode == OP_RRQ) {
        /*
         * Read request - verify that the file exists
         * and that it has world read permission.
         */
        if (stat(filename, &statbuff) < 0) {
            send_ERROR(ERR_ACCESS, strerror(errno));
        }
        if ((statbuff.st_mode & (S_IREAD >> 6)) == 0) {
            send_ERROR(ERR_ACCESS,
                "File doesn't allow world read permission");
        }
    } else if (opcode == OP_WRQ) {
        /*
         * Write request - verify that the directory
         * that the file is being written to has world
         * write permission.  We've already verified above
         * that the filename starts with a '/'.
         */

        char *rindex();

        strcpy(dirname, filename);
        *(rindex(dirname, '/') + 1) = '\0';
        if (stat(dirname, &statbuff) < 0) {
            send_ERROR(ERR_ACCESS, strerror(errno));
        }

        if ((statbuff.st_mode & (S_IWRITE >> 6)) == 0) {
            send_ERROR(ERR_ACCESS,
              "Directory doesn't allow world write permission");
        }
    } else {
        fprintf(stderr, "unknown opcode\n");
    }

    localfp = file_open(filename, (opcode == OP_RRQ) ? "r" : "w", 0);
    if (localfp == NULL) {
        send_ERROR(ERR_NOFILE, strerror(errno));  /* doesn't return */
    }
}

/*
 * Copy a string and convert it to lower case in the process.
 */
void strlccpy(char *dest, char *src)
{
    char c;

    while ((c = *src++) != '\0') {
        if (isupper(c)) {
            c = tolower(c);
        }
        *dest++ = c;
    }
    *dest = 0;
}

/*
 * Send an error packet.
 * Note that an error packet isn't retransmitted or acknowledged by
 * the other end, so once we're done sending it, we can exit.
 */
void send_ERROR(int ecode, char *string)
{
    DEBUG2("sending ERROR, code = %d, string = %s", ecode, string);

    stshort(OP_ERROR, sendbuff);
    stshort(ecode, sendbuff + 2);
    strcpy(sendbuff + 4, string);

    sendlen = 4 + strlen(sendbuff + 4) + 1;     /* +1 for null at end */
    net_send(sendbuff, sendlen);

    net_close();

    exit(EXIT_SUCCESS);
}

/*
 * Return the real (elapsed) time in seconds.
 */
double t_getrtime()
{
    start = ((double) time_start.tv_sec) * 1000000.0 + time_start.tv_usec;
    stop = ((double) time_stop.tv_sec) * 1000000.0 + time_stop.tv_usec;
    seconds = (stop - start) / 1000000.0;

    return seconds;
}
