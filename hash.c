#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include "hash.h"
#include "dir.h"

char *
hex_hash (unsigned char *s) {
    static char h[4];
    unsigned long r = 0;
    for (; *s; s++)
	r += *s;
    snprintf (h, sizeof (h), "%2.2X", (unsigned int) (r & 0xFFUL));
    return h; }

#ifdef STANDALONE
int
main (int argc, char **argv) {
    if (argc > 1) {
	char buf[1024];
	int l;
	unsigned char *s;
	s = (unsigned char *) hex_hash ((unsigned char *) argv[1]);
	snprintf (buf, sizeof (buf), SHEERDNS_DIR "/%s/%s", s, argv[1]);
	mkdir (buf);
	l = strlen ((char *) s);
	write (1, s, l);
	write (1, "\n", 1); }
    return 0; }
#endif
