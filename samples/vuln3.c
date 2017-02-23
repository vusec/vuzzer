#include <stdio.h>
#include <signal.h>

int copyBuff(char *buf, FILE *fp)
{
  fscanf(fp,"%s", buf);
  return 0;
}

int main(int argc, char ** argv)
{

  FILE *fp;
  char buff[1000];
  fp=fopen(argv[1],"r");
  
if (fgetc(fp) == 90)//90=Z
    {
      fscanf(fp, "%s", buff);
      printf("Copied file!\n");
    }
 
else
	{
	printf("Not a valid file\n");
	return 0;
	}
if (buff[8] == 'W')
  {
   printf("1st passed, of course\n");
   if (buff[24]=='Y')
      {
         printf("2nd passed!!\n");
         if(buff[50] == 'T')
          {    
			printf("3rd passed.. going to die..\n");              
			raise(SIGSEGV);
          }
      }
	else{
		printf("INvalid 24th byte..");
		return 0;
		}
   	}
else {
	printf("INvalid 8th byte..");
	return 0;
	}

return 0;
}

