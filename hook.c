#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *gloryhook_strrchr(const char *s, int c){
	printf("STRRCHR HOOKED!\n");
	return strrchr(s, c);
}

char *gloryhook_getenv(const char *name) {
	printf("GETENV HOOKED!\n");
	return getenv(name);
}
