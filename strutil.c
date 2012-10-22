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
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "strutil.h"

void
string_wash (unsigned char *p) {
    unsigned char *q;
    int n;

    assert (p);

    for (n = 0, q = p; *q && n < MAX_RECORD_LEN; q++, n++)
	if (!issuspect (*q))
	    *p++ = *q;
    *p = '\0'; }


void
string_purify (unsigned char *p) {
    unsigned char *q;
    int n;

    assert (p);

    for (n = 0, q = p; *q && n < MAX_RECORD_LEN; q++, n++)
	if (!isevil (*q))
	    *p++ = *q;
    *p = '\0'; }


void
string_chomp (unsigned char *p) {
    unsigned char *q, *t;

    assert (p);

/* skip over leading spaces */
    for (q = p; *q; q++)
	if (!isspace (*q))
	    break;

/* skip over non-space */
    for (t = p; *q;)
	if (!isspace (*p++ = *q++))
	    t = p;

/* truncate trailing space */
    *t = '\0'; }


/* this is quite possibly my favorite function in the whole world */
char **
string_split (const char *s, char c, size_t max, int multi) {
    char *p, **a;
    int n;
    for (n = 0, p = (char *) s; *p && n < max; n++) {
	while (*p && *p != c)
	    p++;
	if (multi) {
	    while (*p && *p == c)
		p++; }
	else if (*p)
	    p++; }
    if (!(a = malloc ((n + 1) * sizeof (char *) + strlen (s) + 1)))
	return 0;
    p = (char *) (&(a[n + 1]));
    for (n = 0; *s && n < max; n++) {
	a[n] = p;
	while (*s && *s != c)
	    *p++ = *s++;
	if (multi) {
	    *p = '\0';
	    while (*s && *s == c) {
		*p++ = '\0';
		s++; }}
	else if (*s) {
	    *p++ = '\0';
	    if (*s == c)
		s++; }
	else {
	    *p = '\0'; }}
    a[n] = 0;
    return a; }

int
string_present (char *s, char **a) {
    int i;
    for (i = 0; a[i]; i++)
	if (!strcmp (a[i], s))
	    return 1;
    return 0; }
