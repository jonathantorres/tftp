#include "tftp.h"

void daemon_start(int ignsigcld);
void net_send(char *buff, int len);
int net_recv(char *buff, int maxlen);
void net_init(char *service, int port);
int net_open(int inetdflag);
void net_close();
int fsm_loop(int opcode);
void send_DATA(int blocknum, int nbytes);
void send_ACK(int blocknum);
int recv_DATA(char *ptr, int nbytes);
int recv_ACK(char *ptr, int nbytes);
void recv_xRQ(int opcode, char *ptr, int nbytes);
void send_ERROR(int ecode, char *string);
void strlccpy(char *dest, char *src);
FILE *file_open(char *fname, char *mode, int initblknum);
void file_close(FILE *fp);
int file_read(FILE *fp, char *ptr, int maxnbytes, int mode);
void file_write(FILE *fp, char *ptr, int nbytes, int mode);
int recv_RRQ(char *ptr, int nbytes);
int recv_WRQ(char *ptr, int nbytes);

struct sockaddr_in tcp_cli_addr;   /* set by accept() */

static int lastcr   = 0;   /* 1 if last character was a carriage-return */
static int nextchar = 0;

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

int main(int argc, char *argv[])
{
    int  childpid;
    char *s;

    fprintf(stderr, "rich's tftpd\n");

    while (--argc > 0 && (*++argv)[0] == '-') {
        for (s = argv[0]+1; *s != '\0'; s++) {
            switch (*s) {
                case 'i':
                    inetdflag = 0;  /* turns OFF the flag (it defaults to 1) */
                    break;
                /* specify server's port# */
                case 'p':
                    if (--argc <= 0) {
                        fprintf(stderr, "-p requires another argument\n");
                        exit(EXIT_FAILURE);
                    }
                    port = atoi(*++argv);
                    break;

                case 't':
                    traceflag = 1;
                    break;

                default:
                    fprintf(stderr, "unknown command line option: %c\n", *s);
            }
        }
    }

    if (inetdflag == 0) {
        /*
         * Start us up as a daemon process (in the background).
         * Also initialize the network connection - create the socket
         * and bind our well-known address to it.
         */
        daemon_start(1);
        net_init(TFTP_SERVICE, port);
    }

    /*
     * If the traceflag is set, open a log file to write to.
     * This is used by the DEBUG macros.  Note that all the
     * err_XXX() functions still get handled by syslog(3).
     */
    if (traceflag) {
        if (freopen(DAEMONLOG, "a", stderr) == NULL) {
            fprintf(stderr, "can't open %s for writing\n", DAEMONLOG);
        }
        DEBUG2("pid = %d, inetdflag = %d", getpid(), inetdflag);
    }

    /*
     * Concurrent server loop.
     * The child created by net_open() handles the client's request.
     * The parent waits for another request.  In the inetd case,
     * the parent from net_open() never returns.
     */
    while (true) {
        if ((childpid = net_open(inetdflag)) == 0) {
            fsm_loop(0); /* child processes client's request */
            net_close(); /* then we're done */
            exit(EXIT_SUCCESS);
        }
        /* parent waits for another client's request */
    }
    return 0;
}

void net_close()
{
    DEBUG2("net_close: host = %s, fd = %d", openhost, sockfd);
    close(sockfd);
    sockfd = -1;
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

void net_init(char *service, int port)
{
    struct servent *sp;

    /*
     * We weren't started by a master daemon.
     * We have to create a socket ourselves and bind our well-known
     * address to it.
     */
    memset((char *) &tcp_srv_addr, 0, sizeof(tcp_srv_addr));
    tcp_srv_addr.sin_family      = AF_INET;
    tcp_srv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (service != NULL) {
        if ((sp = getservbyname(service, "tcp")) == NULL) {
            fprintf(stderr, "net_init: unknown service: %s/tcp\n", service);
            perror("getservbyname error");
            exit(EXIT_FAILURE);
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
               return;
        }
        tcp_srv_addr.sin_port = htons(port);
    }

    /*
     * Create the socket and Bind our local address so that any
     * client can send to us.
     */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("net_init: can't create stream socket");
        exit(EXIT_FAILURE);
    }

    if (bind(sockfd, (struct sockaddr *) &tcp_srv_addr,
             sizeof(tcp_srv_addr)) < 0) {
        perror("net_init: can't bind local address");
        exit(EXIT_FAILURE);
    }

    /*
     * And set the listen parameter, telling the system that we're
     * ready  to accept incoming connection requests.
     */
    listen(sockfd, 5);
}

int net_open(int inetdflag)
{
    int newsockfd, childpid;
    socklen_t clilen;

    if (inetdflag) {
        /*
         * When we're fired up by inetd under 4.3BSD, file
         * descriptors 0, 1 and 2 are sockets to the client.
         */
        sockfd = 0; /* descriptor for net_recv() to read from */
        return 0;   /* done */
    }

    /*
     * For the concurrent server that's not initiated by inetd,
     * we have to wait for a connection request to arrive,
     * then fork a child to handle the client's request.
     * Beware that the accept() can be interrupted, such as by
     * a previously spawned child process that has terminated
     * (for which we caught the SIGCLD signal).
     */
again:
    clilen = (socklen_t) sizeof(tcp_cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr *) &tcp_cli_addr, &clilen);
    if (newsockfd < 0) {
        if (errno == EINTR) {
            errno = 0;
            goto again; /* probably a SIGCLD that was caught */
        }
        perror("accept error");
        exit(EXIT_FAILURE);
    }

    /*
     * Fork a child process to handle the client's request.
     * The parent returns the child pid to the caller, which is
     * probably a concurrent server that'll call us again, to wait
     * for the next client request to this well-known port.
     */
    if ((childpid = fork()) < 0) {
        perror("server can't fork");
        exit(EXIT_FAILURE);
    } else if (childpid > 0) {
        // parent
        close(newsockfd);   /* close new connection */
        return(childpid);   /* and return */
    }

    /*
     * Child process continues here.
     * First close the original socket so that the parent
     * can accept any further requests that arrive there.
     * Then set "sockfd" in our process to be the descriptor that
     * we are going to process.
     */
    close(sockfd);
    sockfd = newsockfd;

    // return to process the connection
    return 0;
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
 * Detach a daemon process from login session context.
 */
void daemon_start(int ignsigcld)
{
    int childpid, fd;

    /*
     * If we were started by init (process 1) from the /etc/inittab file
     * there's no need to detach.
     * This test is unreliable due to an unavoidable ambiguity
     * if the process is started by some other process and orphaned
     * (i.e., if the parent process terminates before we are started).
     */
    if (getppid() == 1) {
        goto out;
    }

    /*
     * Ignore the terminal stop signals (BSD).
     */
#ifdef SIGTTOU
    signal(SIGTTOU, SIG_IGN);
#endif
#ifdef SIGTTIN
    signal(SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTSTP
    signal(SIGTSTP, SIG_IGN);
#endif

    /*
     * If we were not started in the background, fork and
     * let the parent exit.  This also guarantees the first child
     * is not a process group leader.
     */
    if ((childpid = fork()) < 0) {
        perror("can't fork first child");
        exit(EXIT_FAILURE);
    } else if (childpid > 0) {
        // parent
        exit(EXIT_SUCCESS);
    }

    /*
     * First child process.
     *
     * Disassociate from controlling terminal and process group.
     * Ensure the process can't reacquire a new controlling terminal.
     */
#ifdef  SIGTSTP     /* BSD */
    if (setpgrp() == -1) {
        perror("can't change process group");
        exit(EXIT_FAILURE);
    }

    if ((fd = open("/dev/tty", O_RDWR)) >= 0) {
        // lose controlling tty
        ioctl(fd, TIOCNOTTY, NULL);
        close(fd);
    }

#else   /* System V */
    if (setpgrp() == -1) {
        perror("can't change process group");
        exit(EXIT_FAILURE);
    }

    // immune from pgrp leader death
    signal(SIGHUP, SIG_IGN);

    if ((childpid = fork()) < 0) {
        perror("can't fork second child");
        exit(EXIT_FAILURE);
    } else if (childpid > 0) {
        exit(EXIT_SUCCESS);    /* first child */
    }
    /* second child */
#endif

out:
    /*
     * Close any open files descriptors.
     */

    for (fd = 0; fd < NOFILE; fd++) {
        close(fd);
    }

    errno = 0; /* probably got set to EBADF from a close */

    /*
     * Move the current directory to root, to make sure we
     * aren't on a mounted filesystem.
     */
    chdir("/");

    /*
     * Clear any inherited file mode creation mask.
     */
    umask(0);

    /*
     * See if the caller isn't interested in the exit status of its
     * children, and doesn't want to have them become zombies and
     * clog up the system.
     * With System V all we need do is ignore the signal.
     * With BSD, however, we have to catch each signal
     * and execute the wait3() system call.
     */
    if (ignsigcld) {
        signal(SIGCLD, SIG_IGN);    /* System V */
    }
}
