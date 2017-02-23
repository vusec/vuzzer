#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* upcase: Converts input files to upper case.
 * One output file is generated per input file.
 */

int main(int argc, char** argv) {
	FILE *f1, *f2;
	char *f2n;
	int n, c, offset;

	if (argc<2) return 1;
	for (n=1; n<argc; n++) {
		/* create output file name */
		f2n = (char *)malloc((strlen(argv[n])+4)*sizeof(char));
		if (f2n == NULL) return 1;
		sprintf(f2n, "%s.up", argv[n]);
		
		/* open input/output files */
		f1 = fopen(argv[n], "r");
		f2 = fopen(f2n, "w");
		free(f2n);
		if (f1 == NULL || f2 == NULL) return 1;

		/* convert contents */
		while ((c = fgetc(f1)) != EOF) {
			offset = (c>='a' && c<='z') ? 'Z'-'z' : 0;
			fputc(c+offset, f2);
		}
		fclose(f1);
		fclose(f2);
	}
	return 0;
}
