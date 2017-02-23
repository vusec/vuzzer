#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

/* upcase: Converts input files to upper case.
 * One output file is generated per input file.
 */

int main(int argc, char** argv) {
	int f1;
	char buf[1024],buf1[1024];
	char c,d,e;
	f1 = open(argv[1], O_RDONLY);
	read(f1,buf,12);
	if(buf[0]==buf[2]){
		d = buf[1];
	}
	else if(buf[2] == buf[3]){
		d = buf[0];	
	}
	else{
		d = buf[1];
	}
	close(f1);
	return 0;
}
