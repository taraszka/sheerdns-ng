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

void string_purify (unsigned char *s);
void string_chomp (unsigned char *s);

char **string_split (const char *s, char c, size_t max, int multi);
int string_present (char *s, char **a);

/* See section 2.3.1, "Preferred name syntax", of RFC-1035 : */
#define MAX_RECORD_LEN		255
#define isevil(c)						\
	(!(							\
		   ((c) >= 'a' && (c) <= 'z')			\
		|| ((c) >= 'A' && (c) <= 'Z')			\
		|| ((c) >= '0' && (c) <= '9')			\
		||  (c) == '.'					\
		||  (c) == '-'					\
	))

#define issuspect(c)	((c) < ' ' || (c) > '~' || (c) == '/')

