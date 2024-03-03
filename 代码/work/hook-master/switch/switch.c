#include <stdio.h>
#include <string.h>

#define make(_name) \
{                  \
	.name = (_name), \
}
static FILE *fp,*fp1,*fp2 ;
static char s[6];
static char name[56];
int pid;
struct hook_name{
	const char *name;
};

static struct hook_name a[] = {
    make("kernel_clone"),
    make("do_exit"),
    make("do_init_module"),
    make("mprotect_fixup"),
    make("do_execveat_common"),
    make("free_module"),
};

int main(int argc, char** argv)
{ 
   fp = fopen("/proc/input", "w+");
   fp1 = fopen("/proc/output", "r+");
   if(argc!=3 && argc!=2)
   {
     printf("command type error\n");
     return 0;
   }
   
   if(strcmp(argv[1],"-open")==0)
   {
     if(strcmp(argv[2],"-1")==0)
     {
     	fputs("122222", fp);
     }
     if(strcmp(argv[2],"-2")==0)
     {
     	fputs("212222", fp);
     }
     if(strcmp(argv[2],"-3")==0)
     {
     	fputs("221222", fp);
     }
     if(strcmp(argv[2],"-4")==0)
     {
     	fputs("222122", fp);
     }
     if(strcmp(argv[2],"-5")==0)
     {
     	fputs("222212", fp);
     }
     if(strcmp(argv[2],"-6")==0)
     {
     	fputs("222221", fp);
     }
   }
   
   if(strcmp(argv[1],"-close")==0)
   {
     if(strcmp(argv[2],"-1")==0)
     {
     	fputs("022222", fp);
     }
     if(strcmp(argv[2],"-2")==0)
     {
     	fputs("202222", fp);
     }
     if(strcmp(argv[2],"-3")==0)
     {
     	fputs("220222", fp);
     }
     if(strcmp(argv[2],"-4")==0)
     {
     	fputs("222022", fp);
     }
     if(strcmp(argv[2],"-5")==0)
     {
     	fputs("222202", fp);
     }
     if(strcmp(argv[2],"-6")==0)
     {
     	fputs("222220", fp);
     }
     }
     
   if(strcmp(argv[1],"-check")==0)
   {
     fgets(s,6,fp1);
     int i = 0 ,j = 5;
     while(i<=j)
     {
     	if(s[i] == '0')
     	{
     		printf("%s hook is down\n",a[i].name);		
     	}
     	else
     	{
     		printf("%s hook is up\n",a[i].name);	
     	}
     	i++;
     }
   }
   fclose(fp);
   fclose(fp1);
}
