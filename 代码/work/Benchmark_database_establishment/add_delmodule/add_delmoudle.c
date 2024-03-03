#include <stdio.h>
#include <string.h>

static FILE *fp,*fp1;
char name[56];
int main(int argc, char** argv)
{ 
   fp = fopen("/proc/amodule", "w+");
   fp1 = fopen("/proc/dmodule", "w+");
   if(argc!=3 && argc!=2)
   {
     printf("command type error\n");
     return 0;
   }
   
   if(strcmp(argv[1],"-add")==0)
   {
     strcpy(name,argv[2]);
     fputs(name,fp);
   }
   if(strcmp(argv[1],"-del")==0)
   {
     strcpy(name,argv[2]);
     fputs(name,fp1);
   }
   fclose(fp);
   fclose(fp1);

}
