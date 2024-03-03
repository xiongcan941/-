#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static FILE *fp,*fp1;
char mpid[4];
int main(int argc, char** argv)
{ 
   fp = fopen("/proc/aprocess", "w+");
   fp1 = fopen("/proc/dprocess","w+");
   if(argc!=3 && argc!=2)
   {
     printf("command type error\n");
     return 0;
   }
   
   if(strcmp(argv[1],"-add")==0)
   {
     int pid;
     pid = atoi(argv[2]);
     memcpy(&mpid,&pid,4);
     fputs(mpid,fp);
   }
   if(strcmp(argv[1],"-del")==0)
   {
     int pid;
     pid = atoi(argv[2]);
     memcpy(&mpid,&pid,4);
     fputs(mpid,fp1);
   }
   fclose(fp);
   fclose(fp1);
}
