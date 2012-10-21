

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
