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
