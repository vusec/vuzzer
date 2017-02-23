#include <stdio.h>

#define BUFLEN 128

/* Dummy program.
 * Reads data from input file but does not use them to produce
 * the output.
 */

int main(int argc, char** argv) {
	FILE *f1, *f2;
	char b[BUFLEN];
	if (argc < 3) return 1;

	f1 = fopen(argv[1], "r");
	f2 = fopen(argv[2], "w");
	if (f1 == NULL || f2 == NULL) return 1;

	fgets(b, BUFLEN, f1);
	fprintf(f2, "http://bit.ly/ipaw2014\n");
	fclose(f1);
	fclose(f2);

	return 0;
}
