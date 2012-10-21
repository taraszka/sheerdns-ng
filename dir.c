#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <assert.h>
#include "strutil.h"
#include "dir.h"
#include "hash.h"

const char *qtype_name[] = {
    NULL, "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "WKS", "PTR", "HINFO",
    "MINFO", "MX", "TXT", "RP", "AFSDB", "X25", "ISDN", "RT", "NSAP", "NSAP_PTR", "SIG", "KEY", "PX",
    "GPOS", "AAAA", "LOC", "NXT", "EID", "NIMLOC", "SRV", "ATMA", "NAPTR", "KX", "CERT", "A6", "DNAME",
    "SINK", "OPT",
};

/* special reformatting of ptr address - reverse the name:
"2.1.168.192.in-addr.arpa\0" becomes "192.168.1.2\0" */
static char *
try_reverse_in_arpa (char *query) {
    int k, c;
    char new_query[16] = "";
    char *t;
    if (strlen (query) < 12)
	return (char *) strdup (query);
    if (!(t = strstr ((char *) query, "in-addr.arpa")))
	return (char *) strdup (query);
    k = c = (t - query) - 1;
    if (k > 16)
	return (char *) strdup (query);
    for (; k >= 0; k--)
	if (k == 0 || query[k - 1] == '.') {
	    strncat ((char *) new_query, (char *) query + k, c - k);
	    k && strcat ((char *) new_query, ".");
	    c = --k; }
    return (char *) strdup (new_query); }

static int
get_file_name (char *buf, int len, int qtype, unsigned char *s) {
    if (qtype < 1 || qtype > 41)
	return 1;
    s = (unsigned char *) try_reverse_in_arpa ((char *) s);
    if (*s)
	snprintf (buf, len, SHEERDNS_DIR "/%s/%s/%s", hex_hash (s), s, qtype_name[qtype]);
    else
	snprintf (buf, len, SHEERDNS_DIR "/%s", qtype_name[qtype]);
    free (s);
    return 0; }

static void
round_robin (char **s) {
    int n, i;
    char *t;
    for (n = 0; s[n]; n++);
    for (i = 0; i < n * 2; i++) {
	int e;
	e = (long) random () % n;
	t = s[i % n];
	s[i % n] = s[e];
	s[e] = t; }}

char **
directory_lookup (int qtype, unsigned char *s) {
    int fd = -1, c, i;
    char buf[1024];
    char **r, *q = (char *) s;
/* if this is an SOA or NS lookup, we descend through the
domains for any that we are an authority for. this allows
the user to create one NS entry for say test.com and have
that returned as the NS for www.test.com,
ftp.henry.test.com, user1.lab.chemsitry.test.com, etc. :
*/
    while (!get_file_name (buf, sizeof (buf), qtype, (unsigned char *) q)
	   && (fd = open (buf, O_RDONLY)) == -1 && (q = strchr (q, '.')) && q++ && (qtype == REQ_SOA
										    || qtype == REQ_NS));
    if (fd == -1) {
/* try lookup "*.example.com" where asking for "nonexistant.example.com": */
	char *t;
	if (qtype == REQ_SOA || qtype == REQ_NS)	/* probably a bad idea to wildcard these, so return */
	    return NULL;
	q = t = (char *) strdup (s);
	while (*t && *t != '.')
	    t++;
	if (!*t || t == q || !(*--t = '*') || get_file_name (buf, sizeof (buf), qtype, (unsigned char *) t)
	    || (fd = open (buf, O_RDONLY)) == -1) {
	    free (q);
	    return NULL; }
	free (q); }
/* done finding and opening the file, now read the contents: */
    c = read (fd, buf, sizeof (buf));
    close (fd);
    if (c <= 0 || c == sizeof (buf))
	return NULL;
    buf[c] = '\0';
    if (!(r = string_split (buf, '\n', 1000, 1)))
	return NULL;
    if (!r[0]) {		/* is this possible? */
	free (r);
	return NULL; }
    for (i = 0; r[i]; i++) {
	string_chomp ((unsigned char *) r[i]);
	if (qtype == REQ_TXT)
	    string_wash ((unsigned char *) r[i]);
	else
	    string_purify ((unsigned char *) r[i]);
	if (!*(r[i])) {
	    free (r);
	    return NULL; }}
    if (qtype == REQ_A || qtype == REQ_NS)
	round_robin (r);
    return r; }

time_t
get_mtime (int qtype, unsigned char *s) {
    struct stat st;
    char buf[1024];
    if (get_file_name (buf, sizeof (buf), qtype, s))
	abort ();
    if (stat (buf, &st))
	return (time_t) 1000000000UL;
    return st.st_mtime; }
