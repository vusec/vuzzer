#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>

/* A simple grep-like utility.
 * Searches for the specified word in the input files and prints the
 * lines that match. The search is case-insensitive.
 */

int main(int argc, char **argv) {
	int i;
	FILE *f;
	char *word;
	char line[2048];
	char *lline;
	char *c;

	if (argc<2) {
		fprintf(stderr, "Usage: %s <word> <filename1> <filename2> ...\n", argv[0]);
		return -1;
	}

	/* convert word to lowercase */
	for (word=argv[1]; *word != '\0'; word++) *word = tolower(*word);
	word = argv[1];

	/* loop through input files */	
	for (i=2; i<argc; i++) {
		f = fopen(argv[i], "r");
		if (f == NULL) {
			fprintf(stderr, "Error: %s\n", strerror(errno));
			continue;
		}

		while (fgets(line, 2048, f) != NULL) {
			/* convert line to lowercase */
			lline = strdup(line);
			for (c=lline; *c != '\0'; c++) *c = tolower(*c);

			/* print matching lines */
			if (strstr(lline, word)) printf("%s", line);
			free(lline);
		}
		fclose(f);
	}
	return 0;
}
