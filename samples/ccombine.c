#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

/* ccombine: Combines two input files to generate the output.
 * The combination process does not have any usability other than demonstrating
 * the propagation of taint marks within DataTracker.
 */

int main(int argc, char** argv) {
	int in1, in2, out;
	char c1, c2, c;
	if (argc != 4) goto err;

	in1 = open(argv[1], O_RDONLY);
	in2 = open(argv[2], O_RDONLY);
	out = open(argv[3], O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
	if (! (in1 && in2 && out)) goto err;

	while (read(in1, &c1, sizeof(char)) && read(in2, &c2, sizeof(char))) {
		if (c1 == '\n' || c2 == '\n')
			/* implicit value - preserve newlines from either inputs */
			c = '\n';
		else if (c1 == ' ' || c2 == ' ')
			/* implicit value - preserve spaces from either inputs - implicit value */
			c = ' ';
		else if (c1<'a' || c1>'z' || c2<'a' || c2>'z')
			/* implicit value - use a tilde if either input is not a lowercase letter */
			c = '~';
		else if (c1 > c2)
			/* combined value - use values from both inputs to generate output */
			c = 'a' + c1 - c2;
		else
			/* copied value - use the second input */
			c = c2;
		write(out, &c, sizeof(char));
	}

	close(in1);
	close(in2);
	close(out);
	return 0;

	err:
		return 1;
}
				
/*
vim: ai:ts=4:sw=4:noet:ft=c
*/
