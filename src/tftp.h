// Definitions for TFTP client and server.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <setjmp.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>

#define MAXBUFF         2048              /* transmit and receive buffer length */
#define MAXDATA         512              /* max size of data per packet to send or rcv, 512 is specified by the RFC */
#define MAXFILENAME     128              /* max filename length */
#define MAXHOSTNAME     128              /* max host name length */
#define MAXLINE         512              /* max command line length */
#define MAXTOKEN        128              /* max token length */
#define TFTP_SERVICE    "tftp"           /* name of the service */
#define DAEMONLOG       "/tmp/tftpd.log" /* log file for daemon tracing */
#define MODE_ASCII     0                 /* values for modetype, ascii == netascii */
#define MODE_BINARY    1                 /* binary == octet */
#define MAXHOSTNAMELEN 64             /* max size of a host name */
#define MAXBUFF        2048           /* max buffer length */

// TFTP opcodes.
#define OP_RRQ    1   /* Read Request */
#define OP_WRQ    2   /* Write Request */
#define OP_DATA   3   /* Data */
#define OP_ACK    4   /* Acknowledgment */
#define OP_ERROR  5   /* Error, see error codes below also */
#define OP_MIN    1   /* minimum opcode value */
#define OP_MAX    5   /* maximum opcode value */

// Externals
extern char command[];         /* the command being processed */
extern int  connected;         /* true if we're connected to host */
extern char hostname[];        /* name of host system */
extern int  inetdflag;         /* true if we were started by a daemon */
extern int  interactive;       /* true if we're running interactive */
extern jmp_buf  jmp_mainloop;  /* to return to main command loop */
extern int  lastsend;          /* #bytes of data in last data packet */
extern FILE *localfp;          /* fp of local file to read or write */
extern int  modetype;          /* see MODE_xxx values */
extern int  nextblknum;        /* next block# to send/receive */
extern int  port;              /* port number - host byte order, 0 -> use default */
extern char *prompt;           /* prompt string, for interactive use */
extern long totnbytes;         /* for get/put statistics printing */
extern int  traceflag;         /* -t command line option, or "trace" cmd */
extern int  verboseflag;       /* -v command line option */

char *pname;            /* the name by which we are invoked */

// One receive buffer and one transmit buffer.
extern char recvbuff[];
extern char sendbuff[];
extern int  sendlen;    /* #bytes in sendbuff[] */
extern int  op_sent;    /* last opcode sent */
extern int  op_recv;    /* last opcode received */

/*
 * Define the TFTP error codes.
 * These are transmitted in an error packet (OP_ERROR) with an
 * optional netascii Error Message describing the error.
 */
#define ERR_UNDEF   0   /* not defined, see error message */
#define ERR_NOFILE  1   /* File not found */
#define ERR_ACCESS  2   /* Access violation */
#define ERR_NOSPACE 3   /* Disk full or allocation exceeded */
#define ERR_BADOP   4   /* Illegal tftp operation */
#define ERR_BADID   5   /* Unknown TID (port#) */
#define ERR_FILE    6   /* File already exists */
#define ERR_NOUSER  7   /* No such user */

/*
 * Debug macros, based on the trace flag (-t command line argument,
 * or "trace" command).
 */
#define DEBUG(fmt)      if (traceflag) { \
                    fprintf(stderr, fmt); \
                    fputc('\n', stderr); \
                    fflush(stderr); \
                } else { ; }

#define DEBUG1(fmt, arg1)   if (traceflag) { \
                    fprintf(stderr, fmt, arg1); \
                    fputc('\n', stderr); \
                    fflush(stderr); \
                } else { ; }

#define DEBUG2(fmt, arg1, arg2) if (traceflag) { \
                    fprintf(stderr, fmt, arg1, arg2); \
                    fputc('\n', stderr); \
                    fflush(stderr); \
                } else { ; }

#define DEBUG3(fmt, arg1, arg2, arg3)   if (traceflag) { \
                    fprintf(stderr, fmt, arg1, arg2, arg3); \
                    fputc('\n', stderr); \
                    fflush(stderr); \
                } else { ; }

/*
 * Define macros to load and store 2-byte integers, since these are
 * used in the TFTP headers for opcodes, block numbers and error
 * numbers. These macros handle the conversion between host format
 * and network byte ordering.
 */
#define ldshort(addr)       ( ntohs (*( (u_short *)(addr) ) ) )
#define stshort(sval,addr)  ( *( (u_short *)(addr) ) = htons(sval) )

#ifdef  lint        /* hush up lint */
#undef  ldshort
#undef  stshort
short   ldshort();
#endif  /* lint */

/*
 * Structure to contain everything needed for RTT timing.
 * One of these required per socket being timed.
 * The caller allocates this structure, then passes its address to
 * all the rtt_XXX() functions.
 */
struct rtt_struct {
    float rtt_rtt;             /* most recent round-trip time (RTT), seconds */
    float rtt_srtt;            /* smoothed round-trip time (SRTT), seconds */
    float rtt_rttdev;          /* smoothed mean deviation, seconds */
    short rtt_nrexmt;          /* #times retransmitted: 0, 1, 2, ... */
    short rtt_currto;          /* current retransmit timeout (RTO), seconds */
    short rtt_nxtrto;          /* retransmit timeout for next packet, if nonzero */
    struct timeval time_start; /* for elapsed time */
    struct timeval time_stop;  /* for elapsed time */
};

#define RTT_RXTMIN     2    /* min retransmit timeout value, seconds */
#define RTT_RXTMAX     120  /* max retransmit timeout value, seconds */
#define RTT_MAXNREXMT  4    /* max #times to retransmit: must also
                               change exp_backoff[] if this changes */

/*
 * Datatypes of functions that don't return an int.
 */
char *gettoken();
FILE *file_open();
double t_getrtime();   /* our library routine to return elapsed time */

/*
 * user command processing functions.
 */
extern char temptoken[];    /* temporary token for anyone to use */

typedef struct Cmds {
    char *cmd_name;       /* actual command string */
    void  (*cmd_func)();  /* pointer to function */
} Cmds;

extern Cmds commands[];
extern int ncmds;      /* number of elements in array */

extern int rtt_d_flag; /* can be set nonzero by caller for addl info */

int sockfd = -1;                           /* fd for socket of server */
char openhost[MAXHOSTNAMELEN] = { 0 };     /* remember host's name */
struct sockaddr_in   tcp_srv_addr;  /* set by tcp_open() */
struct servent       tcp_serv_info; /* set by tcp_open() */

// initialize variables
char command[MAXTOKEN]      = { 0 };
int connected               = 0;
char hostname[MAXHOSTNAME]  = { 0 };
int inetdflag               = 1;
int interactive             = 1;
jmp_buf jmp_mainloop        = { 0 };
int lastsend                = 0;
FILE *localfp               = NULL;
int modetype                = MODE_ASCII;
int nextblknum              = 0;
int op_sent                 = 0;
int op_recv                 = 0;
int port                    = 0;
char *prompt                = "tftp: ";
char recvbuff[MAXBUFF]      = { 0 };
char sendbuff[MAXBUFF]      = { 0 };
int sendlen                 = 0;
char temptoken[MAXTOKEN]    = { 0 };
long totnbytes              = 0;
int traceflag               = 0;
int verboseflag             = 0;

/*
 * Read "n" bytes from a descriptor.
 * Use in place of read() when fd is a stream socket.
 */
int readn(int fd, char *ptr, int nbytes)
{
    int nleft, nread;

    nleft = nbytes;
    while (nleft > 0) {
        nread = read(fd, ptr, nleft);
        if (nread < 0) {
            return nread;      /* error, return < 0 */
        } else if (nread == 0) {
            break;          /* EOF */
        }

        nleft -= nread;
        ptr   += nread;
    }
    return nbytes - nleft;     /* return >= 0 */
}

/*
 * Write "n" bytes to a descriptor.
 * Use in place of write() when fd is a stream socket.
 */
int writen(int fd, char *ptr, int nbytes)
{
    int nleft, nwritten;

    nleft = nbytes;
    while (nleft > 0) {
        nwritten = write(fd, ptr, nleft);
        if (nwritten <= 0) {
            return nwritten;       /* error */
        }

        nleft -= nwritten;
        ptr   += nwritten;
    }

    return nbytes - nleft;
}
