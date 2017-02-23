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
                printf("%s\n",argv[1]);
                f1 = open(argv[1], O_RDONLY);
                printf("%d\n",f1);
                read(f1,buf,12);
		lseek(f1,16,SEEK_SET);
		read(f1,buf,10);
		c = buf[0];
		d = buf[1];
		e = c + d;
                strcpy(buf1,buf);
                printf("%s\n",buf1);
                printf("%p\n",buf);
                printf("%p\n",&e);
                printf("%p\n",buf1);
		printf("%c\n",e);
                close(f1);
        return 0;
}
