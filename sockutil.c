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

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>

int
listen_socket (char *iface_addr, int listen_port, char *type) {
    struct sockaddr_in a;
    int s;
    if ((s = socket (AF_INET, *type == 'T' ? SOCK_STREAM : SOCK_DGRAM, 0)) < 0) {
	perror ("socket() failed");
	return -1; }
#ifdef SO_REUSEADDR
    {
	int yes = 1;
	if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, sizeof (yes)) < 0) {
	    perror ("setsockopt() failed");
	    close (s);
	    return -1; }}
#endif
    memset (&a, 0, sizeof (a));
    a.sin_port = htons (listen_port);
    a.sin_family = AF_INET;
    if (!inet_aton (iface_addr, &a.sin_addr)) {
	perror ("bad iface address");
	close (s);
	return -1; }
    if (bind (s, (struct sockaddr *) &a, sizeof (a)) < 0) {
	perror ("bind() failed");
	close (s);
	return -1; }
    listen (s, 50);
    printf ("accepting %s packets on addr:port %s:%d\n", *type == 'T' ? "TCP" : "UDP", iface_addr, (int) listen_port);
    return s; }
