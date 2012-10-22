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

#define	REQ_A		1
#define	REQ_NS		2
#define	REQ_CNAME	5
#define	REQ_SOA		6
#define	REQ_PTR		12
#define	REQ_MX		15
#define	REQ_TXT		16

char **directory_lookup (int qtype, unsigned char *s);
time_t get_mtime (int qtype, unsigned char *s);

#define SHEERDNS_DIR	"/var/sheerdns"
