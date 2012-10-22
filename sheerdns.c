/*
 *  Author: Paul Sheer
 *  Modifications: Krzysztof Taraszka
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, version 2.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
 *  02110-1301, USA.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <signal.h>

#include "sockutil.h"
#include "strutil.h"
#include "dir.h"

#define xfree(x)	do { if ((x) && ((char *) (x)) != (char *) extra_results) free(x); (x) = NULL; } while (0)
#define max(a,b)	((a) > (b) ? (a) : (b))

typedef unsigned char u1;
typedef unsigned short u2;
typedef unsigned int u4;

static void make_directories (void);
static int process_packet (int s, u1 * in_buf, int packet_len, char *how, struct sockaddr *from, int fromlen);

enum {
    ANSWERS = 0,
    SERVERS = 1,
    EXTRAS = 2,
    ANS_BLOCKS = 3
};

#define ONE_DAY			(24 * 60 * 60)
#define THREE_DAYS		(3 * 24 * 60 * 60)

static u4 short_time = ONE_DAY;

#define TTL_POLICY(q)		(((q) == REQ_SOA || (q) == REQ_NS) ? THREE_DAYS : short_time)


/* the following values are meaningless, since they all apply to
secondary DNS servers, and we are not using them: */
#define REFRESH			(10 * 60)
#define RETRY			(10 * 60)
#define EXPIRE			(THREE_DAYS)
#define MINTTL			short_time

static int
put_name (u1 * buf, u1 ** here, u1 * name) {
    unsigned int c;
    int i, k, n, offset;
    offset = *here - buf;
    k = 0;
    while ((c = name[k]) != 0) {
	n = 0;
	while ((c = name[k + n]) != 0 && c != '.')
	    n++;
	if (n == 0)
	    break;
	*(*here)++ = (unsigned char) (n & ~0xc0);
	for (i = 0; i < n; i++)
	    *(*here)++ = name[k++];
	if (name[k] == '.')
	    k++; }
    *(*here)++ = 0;
    return offset; }

#define lower_case(c) (((c) >= 'A' && (c) <= 'Z') ? ((c) | 0x20) : (c))

static int
get_name (u1 * msg, u1 ** here, u1 * end, unsigned char *string, int string_len, int k) {
    unsigned int len;
    int i;
    if (*here >= end)
	return -1;
    while ((len = **here) != 0) {
	*here += 1;
	if ((len & 0xc0) == 0xc0) {
	    unsigned int offset;
	    u1 *p;
	    if (*here >= end)
		return -1;
	    offset = ((len & ~0xc0) << 8) + **here;
	    p = &msg[offset];
	    k = get_name (msg, &p, end, string, string_len, k);
	    if (k == -1)
		return k;
	    break; }
	else if ((len & 0xc0)) {
	    return -1; }
	else {
	    for (i = 0; i < len; i++) {
		if (*here >= end)
		    return -1;
		if (k < string_len - 1) {
		    if (isevil (**here))
			return -1;
		    string[k++] = lower_case (**here);
		}
		*here += 1; }
	    if (k < string_len - 1)
		string[k++] = '.'; }}
    *here += 1;
    string[k] = '\0';
    return k; }

void
interrupt (int x) {
    write (2, "exiting\n", 8);
    exit (2); }

struct connection {
    struct connection *next;
    u1 *buf;
    int fd;
    u2 last_activity, len, alloced; };

static struct connection connections = { NULL, (u1 *) "first list item not used" };

int
main (int argc, char **argv) {
    int s, t, fork_twice = 0;
    u2 port = 53;
    u1 in_buf[1536];		/* cannot get packets bigger than this on ethernet */
    char *listen_interface = "0.0.0.0";

    if (argc > 1) {
	int k;
	for (k = 1; k < argc; k++) {
	    if (!strncmp (argv[k], "-d", 2)) {
		fork_twice = 1;
		continue; }
	    if (argv[k][0] == '-' && k > argc - 2)
		goto usage;
	    if (!strncmp (argv[k], "-ttl", 4))
		short_time = (u4) atol (argv[++k]);
	    else if (!strncmp (argv[k], "-p", 2))
		port = (u2) atol (argv[++k]);
	    else if (!strncmp (argv[k], "-i", 2))
		listen_interface = argv[++k];
	    else if (argv[k][0] == '-') {
	      usage:
		fprintf (stderr, "Usage:\n\tsheerdns [-ttl <seconds>] [-p <port>] [-i <iface-ip>] [-d]\n\n");
		exit (1); }}}

    make_directories ();

    chdir(SHEERDNS_DIR);
    if (chroot(SHEERDNS_DIR) != 0) {
	perror("Unable chroot into /var/sheerdns");
        exit (1);
     }

    signal (SIGINT, interrupt);
    signal (SIGPIPE, SIG_IGN);
    signal (SIGHUP, SIG_IGN);
#ifdef SIGTSTP
    signal (SIGTSTP, SIG_IGN);
#endif
#ifdef SIGURG
    signal (SIGURG, SIG_IGN);
#endif

    s = listen_socket (listen_interface, port, "UDP");
    if (s < 0)
	exit (1);
    t = listen_socket (listen_interface, port, "TCP");
    if (t < 0)
	exit (1);

    if (fork_twice) {
	if (fork () > 0)
	    exit (0);
	if (fork () > 0)
	    exit (0); }

    while (1) {
	struct connection *c, *d;
	fd_set fdset;
	int r, f_max;
	time_t current_time_time_t;
	u2 current_time;

	FD_ZERO (&fdset);
	FD_SET (s, &fdset);
	FD_SET (t, &fdset);
	f_max = max (s, t);

#define killtcp(c)						\
	do {							\
	    struct connection *tmp;				\
	    shutdown ((c)->fd, 2), close ((c)->fd);		\
	    tmp = (c)->next, free (c->buf), free (c), (c) = tmp;\
	} while (0)

	for (c = &connections; c->next;) {
	    d = c->next;
	    if ((u2) current_time - d->last_activity > (u2) 30) {	/* idle to long ? */
		killtcp (c->next);
		continue; }
	    else {
		f_max = max (f_max, d->fd);
		FD_SET (d->fd, &fdset); }
	    c = c->next; }

	r = select (f_max + 1, &fdset, NULL, NULL, NULL);
	if (r < 0) {
	    perror ("select");
	    exit (1); }
	if (r == 0) {		/* should not be possible */
	    FD_ZERO (&fdset); }

	time (&current_time_time_t);
	current_time = (u2) (current_time_time_t & 0xFFFF);

/* check to add a new TCP connection: */
	if (FD_ISSET (t, &fdset)) {
	    struct sockaddr_in from;
	    int fromlen = sizeof (from);
	    int fd;
	    memset (&from, 0, fromlen);
	    fd = accept (t, (struct sockaddr *) &from, (void *) &fromlen);
	    if (fd < 0) {
		perror ("accept"); }
	    else {
		c = (struct connection *) malloc (sizeof (struct connection));
		c->fd = fd, c->last_activity = current_time;
		c->len = 0, c->alloced = 2, c->buf = malloc (c->alloced);
		c->next = connections.next;
		connections.next = c; }}

/* check all current TCP connections */
	for (c = &connections; c->next;) {
	    d = c->next;
	    if (FD_ISSET (d->fd, &fdset)) {	/* got data? */
		r = read (d->fd, d->buf + d->len, d->alloced - d->len);
		if (r <= 0 || (!d->len && r != 2 /* first read must be exactly 2 bytes */ )) {
		    killtcp (c->next);
		    continue; }
		d->len += r;
		d->last_activity = current_time;
		if (d->len == 2) {	/* first process the packet size bytes */
		    u2 l;
		    l = (((u2) d->buf[0] << 8) | d->buf[1]);
		    if (l > 1024) {
			killtcp (c->next);
			continue; }
		    d->alloced = l + 2;	/* add two bytes for the packet length */
		    d->buf = realloc (d->buf, d->alloced); }
		else if (d->len == d->alloced) {
		    if (process_packet (d->fd, d->buf + 2, d->len - 2, "TCP", NULL, 0) < d->len) {
			killtcp (c->next);
			continue; }
		    d->len = 0, d->alloced = 2;
		    d->buf = realloc (d->buf, d->alloced); }}			/* ready for next packet */
	    c = c->next; }

	if (FD_ISSET (s, &fdset)) {
	    struct sockaddr_in from;
	    int fromlen = sizeof (from);
	    r = recvfrom (s, in_buf, sizeof (in_buf), 0, (struct sockaddr *) &from, (void *) &fromlen);
	    if (r > 0) {
		memset (in_buf + r, 0, sizeof (in_buf) - r);
		process_packet (s, in_buf, r, "UDP", (struct sockaddr *) &from, fromlen); }}}}

#define er(s)	do { fprintf (stderr, "%s\n", #s); return -1; } while (0)
#define MAX_EXTRA_RESULTS	64

static int
process_packet (int s, u1 * in_buf, int packet_len, char *how, struct sockaddr *from, int fromlen) {
    u1 _out_buf[1536 + 2];	/* cannot get packets bigger than this on ethernet */
    u1 *out_buf = &_out_buf[2];
    u1 query[MAX_RECORD_LEN + 1];
    char *extra_results[MAX_EXTRA_RESULTS];
    char *extra_queries[MAX_EXTRA_RESULTS];
    u4 extra_ttls[MAX_EXTRA_RESULTS];
    int query_len, name_pointer, i, j, extra_results_len = 0;
    u2 id, flags, nqueries, nanswers, nservers, nextras, qtype = 0, orig_qtype = 0, qclass = 0, name_len, *p2;
    u1 *p1, *len_pointer;
/* RFC-1035 says size limit of 512 - we make ours 1024 for both UDP and TCP */
    if (packet_len < 12 || packet_len > 1024)
	er (invalid packet size);

    p2 = (u2 *) in_buf;

    id = ntohs (p2[0]);
    flags = ntohs (p2[1]);
/* get number of queries */
    if (!(nqueries = ntohs (p2[2])))
	er (no queries);
/* get the query string */
    p1 = in_buf + 12;
    memset (query, 0, sizeof (query));
    if (get_name (in_buf, &p1, in_buf + packet_len, query, sizeof (query), 0) == -1)
	er (bad query format);
    query_len = strlen ((char *) query);
    if (*query && query[query_len - 1] == '.')
	query[query_len - 1] = '\0';
/* get the query type */
    qtype = (qtype << 8) | *p1++;
    qtype = (qtype << 8) | *p1++;
    orig_qtype = qtype;
    qclass = (qclass << 8) | *p1++;
    qclass = (qclass << 8) | *p1++;

    nqueries = 1;
    nanswers = 0;
    nservers = 0;
    nextras = 0;

    memset (_out_buf, 0, sizeof (_out_buf));
    p1 = out_buf + 12;

/* query section starts here ----> */
    name_pointer = put_name (out_buf, &p1, query);
    *p1++ = qtype >> 8;
    *p1++ = qtype & 0xFF;
    *p1++ = qclass >> 8;
    *p1++ = qclass & 0xFF;

    if ((flags & 0x8000))	/* response packet - ignoring */
	er (ignoring response packet);

/* now check for valid flags. if not valid, jump over the
part where we fill in the packet: */
    flags &= 0x7900;		/* copy recursive-query-bit, copy opcode-bits */
    flags |= 0x8000;		/* response-bit */

    if (!(qtype == REQ_A || qtype == REQ_PTR || qtype == REQ_MX
	  || qtype == REQ_CNAME || qtype == REQ_NS || qtype == REQ_SOA || qtype == REQ_TXT)) {
	goto empty_packet; }				/* we have none of these records */
    if (qclass != 1 /* class INET */ ) {
	flags |= 4;		/* not supported */
	goto empty_packet; }
    if ((flags & 0x7800) == 1) {	/* inverse query */
	flags |= 4;		/* who supports this ?? */
	goto empty_packet; }
    if ((flags & 0x7800) == 2)	/* status request */
	goto empty_packet;
    if ((flags & 0x7800) != 0)	/* standard query */
	goto empty_packet;

/* answer section starts here ----> */
    extra_results[0] = NULL;
    extra_queries[0] = NULL;

    for (j = 0; j < ANS_BLOCKS; j++) {	/* there are three answer blocks */
	char **lookup_results = NULL;
	u2 *to_incr = NULL;
	switch (j) {
	case ANSWERS:		/* section 1 */
	    to_incr = &nanswers;
	    lookup_results = directory_lookup (qtype, query);

/* a missing a record may be a CNAME - try find it and
then proceed as though we had a CNAME lookup: */
	    if (!lookup_results) {
		qtype = REQ_CNAME;
		xfree (lookup_results);
		lookup_results = directory_lookup (REQ_CNAME, query); }

/* CNAME requires a directly adjacent A record within the
answer section (as per RFC-1034, §3.6.2). This is a
special case, and breaks the elegance of this algorithm.
So we prepend the CNAME answer, and then proceed as though
it were a regular A record (or other record) by replacing
the query with a new query of the canonical name: */
	    if (qtype == REQ_CNAME) {
		if (lookup_results) {
		    nanswers++;
		    put_name (out_buf, &p1, (u1 *) query);
		    *p1++ = qtype >> 8;
		    *p1++ = qtype & 0xFF;
		    *p1++ = qclass >> 8;
		    *p1++ = qclass & 0xFF;
		    *p1++ = (short_time >> 24) & 0xFF;
		    *p1++ = (short_time >> 16) & 0xFF;
		    *p1++ = (short_time >> 8) & 0xFF;
		    *p1++ = (short_time >> 0) & 0xFF;
		    len_pointer = p1;	/* store length of string here */
		    p1 += 2;
		    name_pointer = put_name (out_buf, &p1, (u1 *) lookup_results[0]);	/* <--- replacement of query string with cname (2) */
		    name_len = (p1 - len_pointer) - 2;
		    *len_pointer++ = name_len >> 8;	/* back insert the length */
		    *len_pointer++ = name_len & 0xFF;

/* now proceed as though this were a regular query: */
		    qtype = orig_qtype;
		    strcpy ((char *) query, lookup_results[0]);	/* <--- replacement of query string with cname (2) */
		    xfree (lookup_results);
		    lookup_results = directory_lookup (orig_qtype, query); }}
	    break;
	case SERVERS:		/* section 2 */
	    to_incr = &nservers;
/* append any SOA records possibly present in the
database, but not if the original query was an SOA query,
in which case it would already appear in the section 1: */
	    if (orig_qtype != REQ_SOA) {
		qtype = REQ_SOA;
		lookup_results = directory_lookup (REQ_SOA, query);
/* if we know we are the authority, then we want to be
explicit that the domain really does not exist: */
		if (!nanswers && lookup_results)
		    flags = (flags & ~0xf) | 3; }			/* authoritatively no such domain  */
/* append any NS records possibly present in the database,
but not if the original query was an NS query (in which
case it would already appear in the section 1), or if we
have already added SOA records (because its not really
necessary to add NS records along with NS records): */
	    if (!lookup_results && (orig_qtype != REQ_NS /* don't repeat stuff */ )) {
		xfree (lookup_results);
		qtype = REQ_NS;
		lookup_results = directory_lookup (REQ_NS, query); }
	    break;
	case EXTRAS:		/* section 3 */
	    to_incr = &nextras;
/* any hostnames referenced in the previous two sections
are appended with their proper IP addresses to a list for
inclusion in the last section: */
	    qtype = REQ_A;
	    lookup_results = extra_results;
	    break; }

/* loop through each found record: */
	for (i = 0; lookup_results && lookup_results[i] && i < 256; i++, (*to_incr)++) {
	    u1 *p1_within_512_bytes;
	    u4 ttl;
	    p1_within_512_bytes = p1;	/* psuh the offset in case we overrun */
	    if (j == EXTRAS) {
		ttl = extra_ttls[i];	/* extra section has myriad TTLs */
		put_name (out_buf, &p1, (u1 *) extra_queries[i]); }			/* as well as myriad names */
	    else {
		ttl = TTL_POLICY (qtype);	/* other sections have stock TTLs */
/* pointer to original query string or CNAME result (2), as the case may be: */
		*p1++ = 0xc0 | ((name_pointer >> 8) & ~0xc0);
		*p1++ = (name_pointer & 0xFF); }
	    *p1++ = qtype >> 8;
	    *p1++ = qtype & 0xFF;
	    *p1++ = qclass >> 8;
	    *p1++ = qclass & 0xFF;
	    *p1++ = (ttl >> 24) & 0xFF;
	    *p1++ = (ttl >> 16) & 0xFF;
	    *p1++ = (ttl >> 8) & 0xFF;
	    *p1++ = (ttl >> 0) & 0xFF;
	    len_pointer = p1;	/* store length of string here */
	    p1 += 2;
	    if (qtype == REQ_MX) {	/* for mail servers, prefix with priority number */
		*p1++ = (10 + i * 10) >> 8;
		*p1++ = (10 + i * 10) & 0xFF; }
	    if (qtype == REQ_A) {	/* for A records just store the IP */
		struct in_addr a;
		u1 *q;
		a.s_addr = 0;
		if (!inet_aton (lookup_results[i], &a))
		    flags = (flags & ~0xf) | 1;	/* Format error */
		q = (u1 *) & a.s_addr;
		*p1++ = *q++;	/* already in network byte order */
		*p1++ = *q++;
		*p1++ = *q++;
		*p1++ = *q++; }
	    else if (qtype == REQ_TXT) {	/* for TXT records just store plain text */
		int y;
		for (y = 0; y < 64 && lookup_results[i][y]; y++)
		    p1[y + 1] = (u1) lookup_results[i][y];
		*p1 = y, p1 += y + 1; }
	    else {
		put_name (out_buf, &p1, (u1 *) lookup_results[i]);	/* store string result */
		if (j != EXTRAS) {
		    char **t_results = NULL;
		    if (qtype != REQ_CNAME)	/* CNAMEs IPs are specially appended in the answer section */
			if (!string_present (lookup_results[i], extra_queries))	/* did we already look this one up? */
			    t_results = directory_lookup (REQ_A, (u1 *) lookup_results[i]);	/* lookup any A records available */
		    if (t_results && extra_results_len < MAX_EXTRA_RESULTS - 1) {
			extra_results[extra_results_len] = (char *) strdup ((char *) t_results[0]);
			extra_queries[extra_results_len] = (char *) strdup ((char *) lookup_results[i]);
/* now we need to calculate the ttl's of the extra
section. Our extra section contains only A records of
either an NS, PTR, CNAME, MX, or SOA lookup. NS records
have fixed IP address, and CNAME and SOA records are
fixed. Its only "A" records of REQ_MX, REQ_CNAME, and
REQ_PTR that need a short TTL. This is not exactly
correct, because a CNAME or PTR could actually be a
nameserver, but hay: */
			extra_ttls[extra_results_len] = TTL_POLICY (qtype);
			extra_results_len++;
			extra_results[extra_results_len] = NULL;
			extra_queries[extra_results_len] = NULL; }
		    xfree (t_results); }}

/* for soa records servers we suffix the entry with: mailbox,
serial, refresh, retry, expire, min-ttl: */
	    if (qtype == REQ_SOA) {
		u4 serial;
		time_t tm;
		struct tm *lt;
		lookup_results[i + 1] = NULL;	/* force only one SOA record */
		strcpy ((char *) p1, "\012hostmaster");
		p1 += 11;
		put_name (out_buf, &p1, (u1 *) lookup_results[i]);	/* store string result */
		tm = (time_t) get_mtime (REQ_SOA, (unsigned char *) query);
		lt = localtime (&tm);
/* hack a serial number from the modified time of the file - this
has a resolution of 32 seconds and looks like YYYYppnnnn where
pp.nnnn is the percentage of the year passed: */
		serial =
		    ((u4) lt->tm_year + 1900) * 1000000 + ((u4) ((u4) lt->tm_yday * 24 * 3600 +
								 lt->tm_hour * 3600 + lt->tm_min * 60 +
								 lt->tm_sec) >> 5);
		*p1++ = (serial >> 24) & 0xFF;
		*p1++ = (serial >> 16) & 0xFF;
		*p1++ = (serial >> 8) & 0xFF;
		*p1++ = (serial >> 0) & 0xFF;
		*p1++ = (REFRESH >> 24) & 0xFF;
		*p1++ = (REFRESH >> 16) & 0xFF;
		*p1++ = (REFRESH >> 8) & 0xFF;
		*p1++ = (REFRESH >> 0) & 0xFF;
		*p1++ = (RETRY >> 24) & 0xFF;
		*p1++ = (RETRY >> 16) & 0xFF;
		*p1++ = (RETRY >> 8) & 0xFF;
		*p1++ = (RETRY >> 0) & 0xFF;
		*p1++ = (EXPIRE >> 24) & 0xFF;
		*p1++ = (EXPIRE >> 16) & 0xFF;
		*p1++ = (EXPIRE >> 8) & 0xFF;
		*p1++ = (EXPIRE >> 0) & 0xFF;
		*p1++ = (MINTTL >> 24) & 0xFF;
		*p1++ = (MINTTL >> 16) & 0xFF;
		*p1++ = (MINTTL >> 8) & 0xFF;
		*p1++ = (MINTTL >> 0) & 0xFF; }

	    name_len = (p1 - len_pointer) - 2;
	    *len_pointer++ = name_len >> 8;	/* back insert the length */
	    *len_pointer++ = name_len & 0xFF;
	    if ((p1 - out_buf) > (*how == 'T' ? 1024 : 512)) {	/* limit to 1024 bytes for TCP, 512 for UDP */
		p1 = p1_within_512_bytes;
		*how == 'U' && (flags |= 0x0200 /* truncation bit */ );	/* for TCP we are silent about the truncation */
		/* do not increment (*to_incr), and then */
		xfree (lookup_results);
		goto break_2; }}
	xfree (lookup_results); }
  break_2:
    while (--extra_results_len >= 0) {
	assert (extra_results[extra_results_len]);
	assert (extra_queries[extra_results_len]);
	free (extra_results[extra_results_len]);
	free (extra_queries[extra_results_len]);
	extra_results[extra_results_len] = NULL;
	extra_queries[extra_results_len] = NULL; }
    packet_len = (p1 - out_buf);

    if (nanswers || nservers) {
	flags |= 0x0400; }				/* authority-bit 0x0400 */

  empty_packet:
    p1 = out_buf;		/* goto start of packet to fill in total counts */
    *p1++ = id >> 8;
    *p1++ = id & 0xFF;
    *p1++ = flags >> 8;
    *p1++ = flags & 0xFF;
    *p1++ = nqueries >> 8;
    *p1++ = nqueries & 0xFF;
    *p1++ = nanswers >> 8;
    *p1++ = nanswers & 0xFF;
    *p1++ = nservers >> 8;
    *p1++ = nservers & 0xFF;
    *p1++ = nextras >> 8;
    *p1++ = nextras & 0xFF;

/* finally... */
    if (*how == 'T' /* TCP */ ) {
	out_buf -= 2;
	out_buf[0] = (packet_len >> 8);
	out_buf[1] = (packet_len & 0xFF);
/* this assumes the OS queue can hold our data without
blocking. for 1026 bytes or less, we are pretty sure it
can. */
	return send (s, out_buf, packet_len + 2, 0); }
    else {			/* UDP */
	return sendto (s, out_buf, packet_len, 0, from, fromlen); }}


static void
make_directories (void) {
    const char *hex = "0123456789ABCDEF";
    char path[256];
    int j, fd, l;
    mkdir (SHEERDNS_DIR, 0700);
    mkdir (SHEERDNS_DIR "/default", 0700);
    strcpy (path, SHEERDNS_DIR);
    mkdir (path, 0700);
    l = strlen (path);
    for (j = 0; j < 256; j++) {
	path[l] = '/';
	path[l + 1] = hex[j >> 4];
	path[l + 2] = hex[j & 0xF];
	path[l + 3] = '\0';
	mkdir (path, 0700); }
    mkdir (SHEERDNS_DIR "/C9/localhost", 0700);
    fd = open (SHEERDNS_DIR "/C9/localhost/A", O_WRONLY | O_CREAT | O_TRUNC, 0700);
    write (fd, "127.0.0.1", 9);
    close (fd);
    mkdir (SHEERDNS_DIR "/7A/localhost.localdomain", 0700);
    fd = open (SHEERDNS_DIR "/7A/localhost.localdomain/A", O_WRONLY | O_CREAT | O_TRUNC, 0700);
    write (fd, "127.0.0.1", 9);
    close (fd);
    mkdir (SHEERDNS_DIR "/B5/127.0.0.1", 0700);
    fd = open (SHEERDNS_DIR "/B5/127.0.0.1/PTR", O_WRONLY | O_CREAT | O_TRUNC, 0700);
    write (fd, "localhost", 9);
    close (fd); }
