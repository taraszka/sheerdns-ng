
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

