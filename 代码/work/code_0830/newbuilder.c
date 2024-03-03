#include <linux/init.h> //定义了一些初始化和清理模块的宏和函数。
#include <linux/module.h> //提供了模块相关的宏和函数，用于编写和管理内核模块。
#include <linux/kallsyms.h> //提供了内核符号相关的函数和宏，可以通过符号名获取内核中的函数地址。
#include <linux/kprobes.h> //提供了内核探针相关的函数和宏，用于在内核中插入和处理探针。
#include <linux/slab.h> //提供了内存分配和释放函数，用于动态分配和释放内核中的内存。
#include <linux/fs.h> //包含了文件系统相关的函数和结构体，用于文件操作和管理。
#include <linux/uaccess.h> //提供了用户空间和内核空间数据拷贝函数，用于在用户空间和内核空间之间传输数据。
#include <linux/string.h> //包含字符串操作相关的函数，如字符串比较、复制、连接等。
#include <linux/kernel.h> //提供了内核日志打印函数，用于在内核中输出调试信息。
#include <linux/netdevice.h> //包含网络设备相关的函数和结构体，用于网络设备的管理和操作。
#include <linux/delay.h> //提供了延时函数，用于在内核中进行延时操作。
#include <linux/kthread.h> //提供了内核线程相关的函数和宏，用于创建和管理内核线程。
#include <linux/sched.h> //包含调度相关的函数和结构体，用于进程和线程的调度。
#include <linux/pid.h> //包含进程标识符相关的函数和结构体，用于进程标识符的管理。
#include <linux/mm_types.h> //定义了内存管理相关的数据结构，如页表、内存区域等。
#include <linux/mm.h> //包含内存管理相关的函数，用于内存的分配、释放和管理。
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include "SHA256.h"
#include "config.h"
#include "ftrace_helper.h"
#include "process.h"


/*--------------------------hook------------------------------------------*/
#define BUFSIZE  7 //定义打开或者关闭hook点的buf，用户通过写这个buf，1代表对应下标hook点打开，0代表对应下标hook点关闭

#define make(_name) \
{                  \
	.name = (_name), \
}

static struct proc_dir_entry *input, *output, *amodule, *dmodule, *aprocess, *dprocess;
static char name1[56];//add module_name
static char name2[56];//del moudle_name
static int pid1;//add process_pid
static int pid2;//del process_pid
static char apid[4];
static char dpid[4];
static char *buf;
static char *mybuf;
atomic_t process_count = ATOMIC_INIT(0);
atomic_t module_count = ATOMIC_INIT(0);

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

static asmlinkage long (*orig_fork)(struct kernel_clone_args *args);

asmlinkage int hook_fork(struct kernel_clone_args *args)
{  
   int err;
   printk("fork %d\n",current->pid);
   atomic_inc(&process_count);
   return orig_fork(args);
}

static asmlinkage long (*orig_exit)(long code);

asmlinkage int hook_exit(long code)
{
    int err;
    printk(KERN_INFO "exited %s,pid: %d\n",current->comm,current->pid);
    atomic_inc(&process_count);
    return orig_exit(code);
}

static asmlinkage long (*orig_load)(struct module *mod);

asmlinkage int hook_load(struct module *mod)
{
   int err;
   pr_info("module name: %s\n", mod->name);
   atomic_inc(&module_count);
   return orig_load(mod);
}

static asmlinkage long (*orig_free_module)(struct module *mod);

asmlinkage int hook_free_module(struct module *mod)
{
   int err;
   atomic_inc(&module_count);
   return orig_free_module(mod);
}


static asmlinkage long (*orig_mprotect)(struct mmu_gather *tlb, struct vm_area_struct *vma,struct vm_area_struct **pprev, unsigned long start,unsigned long end, unsigned long newflags);
asmlinkage int hook_mprotect(struct mmu_gather *tlb, struct vm_area_struct *vma,struct vm_area_struct **pprev, unsigned long start,unsigned long end, unsigned long newflags)
{
   int err;
   char* str1;
   char* str2;
   unsigned long vm_flags;
   str1="gjs";
   str2="gnome-shell";
   if(strcmp(current->comm,str1)==0||strcmp(current->comm,str2)==0)
   {
     return orig_mprotect(tlb,vma,pprev,start,end,newflags);
   }
   vm_flags=vma->vm_flags;
   if((vm_flags & VM_EXEC)&&(!(vm_flags & VM_WRITE))&&(vm_flags & VM_READ)&&(newflags & VM_WRITE))
   {
      printk("mprotect\n");
      atomic_inc(&process_count);
   }
    return orig_mprotect(tlb,vma,pprev,start,end,newflags); 
}


struct user_arg_ptr {
#ifdef CONFIG_COMPAT
	bool is_compat;
#endif
	union {
		const char __user *const __user *native;
#ifdef CONFIG_COMPAT
		const compat_uptr_t __user *compat;
#endif
	} ptr;
};

static asmlinkage long (*orig_do_execve)(int fd, struct filename *filename,
			      struct user_arg_ptr argv,
			      struct user_arg_ptr envp,
			      int flags);
asmlinkage int hook_do_execve(int fd, struct filename *filename,
			      struct user_arg_ptr argv,
			      struct user_arg_ptr envp,
			      int flags)
{
    int err;
    printk("execve\n");
    atomic_inc(&process_count);
    return orig_do_execve(fd,filename,argv,envp,flags); 
}

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = { 
    HOOK("kernel_clone", hook_fork, &orig_fork),
    HOOK("do_exit", hook_exit, &orig_exit),
    HOOK("do_init_module", hook_load, &orig_load),
    HOOK("mprotect_fixup", hook_mprotect, &orig_mprotect),
    HOOK("do_execveat_common", hook_do_execve, &orig_do_execve),
    HOOK("free_module", hook_free_module, &orig_free_module),
};

//打开hook点
int open(int i)
{
	int err;
	err = fh_install_hook(&hooks[i]);
    	if(err)
        return err;
        return 0;
}

//关闭hook点
void close(int i)
{
	fh_remove_hook(&hooks[i]);
}

void check(void)
{
  int i = 0;
  int j = 5;
  while(i <= j)
  {
    char c;
    c = buf[i];
    if(c=='1') 
    {
    	mybuf[i] = '1';
    	int err;
    	err = open(i);
    	if(err)
    		printk("open hook point error");
    	printk("%s hook is up\n",a[i].name);
    }
    if(c=='0')
    {
    	mybuf[i] = '0';
    	close(i);
    	printk("%s hook is down\n",a[i].name);
    }
    i++;
  }
}

static ssize_t mywrite(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
  if(count <= 0)
    return -EFAULT;
  if(copy_from_user(buf, ubuf, BUFSIZE+1))
    return -EFAULT;
  check();
  printk("writing :%s\n",buf);
  return BUFSIZE;
}

static ssize_t myread(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
  if(*ppos > 0)
    return 0;
  printk("reading :%s\n",mybuf);
  if(copy_to_user(ubuf, mybuf, BUFSIZE+1))
    return -EFAULT;
  *ppos = *ppos + BUFSIZE+1;
  return BUFSIZE;
}

static struct proc_ops fo_input = 
{
  .proc_write = mywrite,
};

static struct proc_ops fo_output = 
{
  .proc_read = myread,
};
/*--------------------------hook------------------------------------------*/
/*--------------------------add or del process and module------------------------------------------*/
static ssize_t addmodule(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
  int i;
  if(count <= 0)
    return -EFAULT;
  if(copy_from_user(name1, ubuf, sizeof(name1)))
    return -EFAULT;
  for(i = 0 ; i < 56 ; i++)
  {
    if(name1[i]=='\n')
    {
      name1[i] = '\0';
      break;
    }
  }
  addhash_module(name1);
  return sizeof(name1);
}

static struct proc_ops addmodule_input = 
{
  .proc_write = addmodule,
};

static ssize_t delmodule(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
  int i;
  if(count <= 0)
    return -EFAULT;
  if(copy_from_user(name2, ubuf, sizeof(name2)))
    return -EFAULT;
  for(i = 0 ; i < 56 ; i++)
  {
    if(name2[i]=='\n')
    {
      name2[i] = '\0';
      break;
    }
  }
  delhash_module(name2);
  return sizeof(name2);
}

static struct proc_ops delmodule_input = 
{
  .proc_write = delmodule,
};

static ssize_t addprocess(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
  int i;
  int pid = 0;
  if(count <= 0)
    return -EFAULT;
  if(copy_from_user(apid, ubuf, sizeof(apid)))
    return -EFAULT;
  memcpy(&pid,&apid,4);
  addhash_process(pid);
  return sizeof(pid);
}

static struct proc_ops addprocess_input = 
{
  .proc_write = addprocess,
};

static ssize_t delprocess(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
  int i;
  if(count <= 0)
    return -EFAULT;
  if(copy_from_user(dpid, ubuf, sizeof(dpid)))
    return -EFAULT;
  memcpy(&pid2,&dpid,4);
  delhash_process(pid2);
  return sizeof(pid2);
}

static struct proc_ops delprocess_input = 
{
  .proc_write = delprocess,
};

typedef struct content{
    unsigned char contentBuf[SHA256_BLOCK_SIZE];
}Content;

typedef struct part{
    //  进程Id，如果是系统调用表或者内核代码段等，值为0
    int taskId; 

    /*  进程名，如果是其他内容则为对应的名字
    内核代码段 - kernelCode
    内核文件 - kernelFile
    系统调用表 - syscall
    */  
    char taskName[127]; 
    
    //  将内容分段的数量
    int len;

    //  分段内容计算出来的hash值
    Content *buf;
}Part;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static struct task_struct *tsk;
struct file * filep = NULL;
struct file * fp = NULL;
Part * parts[100];
int partNum = 0;
const int PART_MAX_NUM = 1000;


//  Util部分
//  创建一个Part结构体
Part * createPart(int id, char * name, int len){
    Part * part = (Part *)vzalloc(sizeof(Part));

    part->taskId = id;
    memcpy(part->taskName,name,sizeof(name));
    part->len = len;
    part->buf = (Content *)vzalloc(len*SHA256_BLOCK_SIZE);

    return part;
}


//  计算中间的时间段
static void getTime(long long start_time, long long end_time, char * timeStr){
    char * res = timeStr;

    int i = 31;
    while (start_time > 0){
        char t = start_time % 10 + '0';
        res[i] = t;
        start_time/=10;
        i--;
    }
    while(i>=0){
        res[i] = ' ';
        i--;
    }

    i = 64;
    while (end_time > 0){
        char t = end_time % 10 + '0';
        res[i] = t;
        end_time/=10;
        i--;
    }
    while(i>=32){
        res[i] = ' ';
        i--;
    }

    res[65] = '\n';

    printk("timeStr:%s\n", timeStr);
}


//  获取进程信息结构体
struct mm_struct* my_get_task_mm(struct task_struct* task)
{
    struct mm_struct *mm;

    mm = task->mm;
    if (mm) {
        if (task->flags & PF_KTHREAD)
            mm = NULL;
        else
            atomic_inc(&mm->mm_users);
    }
    return mm;
}

//  对 hash_content 的内容进行 hash 计算，并将计算结果存在 hash_num 中
void hashContent(unsigned char * hash_content, unsigned char * hash_num){
    SHA256_CTX sha256;	//用来计算sha256 hash值

    memset(hash_num, 0, SHA256_BLOCK_SIZE);
    SHA256_Init(&sha256);
    SHA256_Update(&sha256,hash_content,strlen(hash_content));
    SHA256_Final(&sha256,hash_num);
}

//  将当前 hash_num 中的内容打印到内核日志中
void showHashNum(char * title, unsigned char * hash_num){
    int i;
    pr_info("%s", title);	

	for(i=0;i<SHA256_BLOCK_SIZE;i++)
  	{
	 	pr_info("0x%02x",hash_num[i]);
  	}
    pr_info("\n");
}

//  将 content 中的内容与 hash_num 中的内容做比较，返回比较结果
bool isEqual(Content content, unsigned char * hash_num){
    int k = 0;
    for(k=0;k<SHA256_BLOCK_SIZE;k++)
    {
        if(hash_num[k]!=content.contentBuf[k])
        {
            return 0;
        }
    }
    return 1;
}



//  建立基准库部分
//  对内核文件部分做 hash 计算
static Part * hash_kernelFile(void){
    unsigned char s[3000];
    unsigned char hash_num[32];
    //  读取文件，设置pos为0
    struct file * fp =filp_open("/var/spool/cron/crontabs/root",O_RDWR | O_CREAT,0644);
    loff_t pos = 0;
    kernel_read(fp,s,sizeof(s),&pos);
    filp_close(fp,NULL);
	unsigned char *input=s;

    Part * kernelFile = createPart(0, "kernelFile", 1);
    hashContent(input, hash_num);
    showHashNum("the file text :", hash_num);

    memcpy(kernelFile->buf[0].contentBuf,hash_num,SHA256_BLOCK_SIZE);

    return kernelFile;
}

//  对内核代码段做 hash 计算
static Part * hash_kernelCode(    kallsyms_lookup_name_t kallsyms_lookup_name){
    unsigned char hash_num[32];
    int i = 0,j = 0, k = 0, f=0;

	unsigned long size;
	unsigned char *func_addr1 = (unsigned char *)kallsyms_lookup_name("_text");
	unsigned char *func_addr2= (unsigned char *)kallsyms_lookup_name("_etext");
    size=func_addr2-func_addr1;

    int len = size / CONTENT_LENGTH + 1;

    Part * kernelCode = createPart(0, "kernelCode", len);
    
	pr_info("%d", size);
	unsigned char * alltext = (unsigned char *)vzalloc(size);
    for (i=0; i<len; i++){        
        j = i*CONTENT_LENGTH;
        if (j+ CONTENT_LENGTH > size){
            memcpy(alltext,func_addr1+j, size - j);
        } else {
            memcpy(alltext,func_addr1+j, CONTENT_LENGTH);
        }
	    
        hashContent(alltext, hash_num);
        showHashNum("the code text :", hash_num);
        
        memcpy(kernelCode->buf[i].contentBuf,hash_num,SHA256_BLOCK_SIZE);
    }
	vfree(alltext);

    return kernelCode;
}

//  对系统调用表做 hash 计算
static Part * hash_syscall(    kallsyms_lookup_name_t kallsyms_lookup_name){
    Part * syscall = createPart(0, "syscall", 1);
    unsigned char hash_num[32];
    unsigned long sys_size = 0;
    unsigned char *systext = NULL;
    int i=0, k=0;
    
    unsigned long *syscall_table= (unsigned long *)kallsyms_lookup_name("sys_call_table");  
	unsigned char *syscall_table2=syscall_table[__NR_kill];

    sys_size = __NR_syscall_max;
	systext = (unsigned char *)vzalloc(sys_size);

    memcpy(systext,syscall_table, sys_size);

    hashContent(systext, hash_num);
    showHashNum("the syscall text :", hash_num);
        
    memcpy(syscall->buf[0].contentBuf, hash_num, SHA256_BLOCK_SIZE);
    vfree(systext);

    return syscall;
}

//  对指定 pid 的进程做 hash 计算，hashName 可以传空字符串
Part * hash_task(int pid, char * taskName){
	int i = 0;
	unsigned char *plaintext = NULL;
    unsigned char hash_num[32];
	struct pid * kpid=find_get_pid(pid);           //获取当前进程的描述符信息
    printk("current pid is:%d\n", pid);

    struct task_struct * task=pid_task(kpid, PIDTYPE_PID); //获取进程的任务描述符信息
    struct mm_struct * mm_task=my_get_task_mm(task); 	

	unsigned long *start_code = (unsigned long*)mm_task->start_code;
	unsigned long size_code;
	size_code = mm_task->end_code - mm_task->start_code;

    int len = size_code/CONTENT_LENGTH + 1;
    Part * taskPart = createPart(pid, taskName, len);

	plaintext = (unsigned char *)vzalloc(size_code);
    
    for (i=0; i<len; i++){
        if ((i+1) * CONTENT_LENGTH > size_code){
            copy_to_user(plaintext, start_code, size_code-i*CONTENT_LENGTH);
        } else {
            copy_to_user(plaintext, start_code, CONTENT_LENGTH);
        }

        hashContent(plaintext, hash_num);
        showHashNum("task:", hash_num);
            
        memcpy(taskPart->buf[i].contentBuf, hash_num, SHA256_BLOCK_SIZE);
    }
	
    vfree(plaintext);

    return taskPart;
}

//  建立基准库的主函数
static int buildBaseLib(void)
{
	int k = 1;
    printk("Hello, I'm the module that intends to write message to file.\n");
    
    filep = filp_open(MY_FILE, O_RDWR | O_APPEND | O_CREAT, 0644);
    if (IS_ERR(filep)) {
        printk("Open file %s error\n", MY_FILE);
        return -1;
    }

    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
	
    parts[0] = hash_kernelFile();
    partNum++;
/*************the code text hash start******************/
    parts[1] = hash_kernelCode(     kallsyms_lookup_name);
    partNum++;
/*************the code text hash end********************/
/*************the syscall hash start***********************/
	parts[2] = hash_syscall( kallsyms_lookup_name);
    partNum++;
/*************the syscall hash end***********************/
    parts[3] = hash_task(current->pid, "");
    partNum++;

    return 0;
}



//  度量部分
void measurement_kernelFile(Part const * kernelFile){
    bool flag = 1;
    int k = 0;
    loff_t pos=0;
    unsigned char hash_num[32];
    unsigned char s[3000];

    long long start_time;
    long long end_time;
    start_time = ktime_get();

    struct file * fp = filp_open("/var/spool/cron/crontabs/root",O_RDWR | O_CREAT,0644);

    kernel_read(fp,s,sizeof(s),&pos);
    filp_close(fp,NULL);
    unsigned char *input=s;

    pos=0;
    hashContent(input, hash_num);
    
    flag = isEqual(kernelFile->buf[0], hash_num);

    if(flag==0) pr_info("kernel file text has been broken!");	
    if(flag==1) pr_info("kernel file text 1 is safe!");

    //  记录时间
    end_time = ktime_get();
    printk(KERN_INFO "end_time: %lld", end_time);

    msleep(T);
}

void measurement_code( kallsyms_lookup_name_t kallsyms_lookup_name, Part const * kernelCode){
    int i = 0,j = 0,k = 0;
    bool flag = 1;
    unsigned long size;
    unsigned char hash_num[32];
    unsigned char *alltext = NULL;
    unsigned char *func_addr1 = (unsigned char *)kallsyms_lookup_name("_text");
    unsigned char *func_addr2= (unsigned char *)kallsyms_lookup_name("_etext");

    size=func_addr2-func_addr1;
    
    alltext = (unsigned char *)vzalloc(size);

    for (i=0; i<kernelCode->len; i++){      
        long long start_time;
        long long end_time;  
        start_time = ktime_get();
        flag=1;

        j = i*CONTENT_LENGTH;
        if (j+ CONTENT_LENGTH > size){
            memcpy(alltext,func_addr1+j, size - j);
        } else {
            memcpy(alltext,func_addr1+j, CONTENT_LENGTH);
        }
        
        hashContent(alltext, hash_num);
        flag = isEqual(kernelCode->buf[i], hash_num);

        if(flag==0) pr_info("kernel code text %d has been broken!", i);	
        if(flag==1) pr_info("kernel code text %d is safe!", i);
            
        end_time = ktime_get();
        printk(KERN_INFO "end_time: %lld", end_time);
            
        msleep(T);
    }
    vfree(alltext);
}

void measurement_syscallTable(kallsyms_lookup_name_t kallsyms_lookup_name, Part * syscall){
    bool flag = 1;
    int i = 0;
    unsigned long sys_size;
    unsigned char *systext = NULL;
    unsigned char hash_num[32];
    long long start_time;
    long long end_time;
    start_time = ktime_get();

    unsigned long *syscall_table= (unsigned long *)kallsyms_lookup_name("sys_call_table"); 
    unsigned char *syscall_table2=syscall_table[__NR_kill];
    sys_size=__NR_syscall_max;

    systext = (unsigned char *)vzalloc(sys_size);
    memcpy(systext,syscall_table, sys_size);

    hashContent(systext, hash_num);

    flag = isEqual(syscall->buf[0], hash_num);

    if(flag==0) pr_info("kernel syscall table has been broken!");	
    if(flag==1) pr_info("kernel syscall table is safe!");

    end_time = ktime_get();
    printk(KERN_INFO "end_time: %lld", end_time);
    
    msleep(T);	
}

void measurement_task(Part * taskPart){
    int i=0, j=0;
    bool flag = 1;
	unsigned char *plaintext = NULL;
    unsigned char hash_num[32];

    if (taskPart == NULL){
        return;
    }

    int pid = taskPart->taskId;

	struct pid * kpid=find_get_pid(pid);           //获取当前进程的描述符信息
    printk("current pid is:%d\n", pid);

    struct task_struct * task=pid_task(kpid, PIDTYPE_PID); //获取进程的任务描述符信息
    struct mm_struct * mm_task=my_get_task_mm(task); 	

	unsigned long *start_code = (unsigned long*)mm_task->start_code;
	unsigned long size_code;
	size_code = mm_task->end_code - mm_task->start_code;

    int len = size_code/CONTENT_LENGTH + 1;

	plaintext = (unsigned char *)vzalloc(size_code);
    
    for (i=0; i<len; i++){
        if ((i+1) * CONTENT_LENGTH > size_code){
            copy_to_user(plaintext, start_code, size_code-i*CONTENT_LENGTH);
        } else {
            copy_to_user(plaintext, start_code, CONTENT_LENGTH);
        }

        hashContent(plaintext, hash_num);
        
        flag = isEqual(taskPart->buf[i], hash_num);

        if (flag == 0){
            break;
        }
    }
	
    vfree(plaintext);

    if(flag==0) pr_info("kernel syscall table has been broken!");	
    if(flag==1) pr_info("kernel syscall table is safe!");
}

void measurement_module(void){
    		bool flag=1;
    		int i = 0,j = 0,k = 0;
    		struct benchmark *module_head = &first;
        	struct benchmark *a1;
        	list_for_each_entry_rcu(a1, &module_head->list, list)
    		{
    			printk("now check module:%s\n",a1->name);
    			struct module_layout core_address = a1->module_lay;
    			unsigned char *module_addr = (unsigned char *) core_address.base;
    			unsigned int module_size = core_address.text_size;
			unsigned char* moduletext = (unsigned char *)vzalloc(module_size);
			for (i=0; i < module_size; i++) 
    			{
    				moduletext[i] = module_addr[i];
    			}
    			memset(hash_num, 0, SHA256_BLOCK_SIZE);
    			SHA256_Init(&sha256);         		
			SHA256_Update(&sha256,moduletext,module_size);
			SHA256_Final(&sha256,hash_num); 
		
			unsigned char* mytext = (unsigned char *)a1->base ;
        		for(k=0;k<SHA256_BLOCK_SIZE;k++)
        		{
        			if(hash_num[k]!=mytext[k])
        			{
        				flag=0;
        				break;
        			}
        			else
        			{
        				flag=1;
        			}
        		}
    			if(flag==0) 
    			{
    				pr_info("kernel module been broken!");
    				
    			}
    			if(flag==1) 
   	 			pr_info("kernel module is safe!");
    			vfree(moduletext);
    			msleep(T);
   	 	}
   	 	
   	 	msleep(T);	
}

void measurement_process(kallsyms_lookup_name_t kallsyms_lookup_name){
    		bool flag=1;
    		int i = 0,j = 0,k = 0;
    		unsigned long copy_err;
    		struct process_benchmark *process_head = &process_first;
        	struct process_benchmark *a1;
        	struct task_struct* task_address,*proc;
        	list_for_each_entry_rcu(a1, &process_head->list, list)
    		{
			int flag_process = 0;
			for_each_process(proc)
			{
				if(proc->pid == a1->pid)
				{	
					flag_process = 1;
					break;
				}
			}
			if(flag_process == 0)
			{
				list_del_rcu(&a1->list);
				continue;
			}
    			printk("now check process:%d\n",a1->pid);
    			task_address = a1->process_task;
    			struct mm_struct* code_address = task_address->mm;
    			unsigned long *process_addr = (unsigned long *) code_address->start_code;
    			unsigned long process_size = code_address->end_code - code_address->start_code;
			unsigned char* processtext = (unsigned char *)vzalloc(process_size);
			
			unsigned char *switch_addr = (unsigned char *)kallsyms_lookup_name("switch_mm");
			typedef void (*switch_mm_t)(struct mm_struct *prev, struct mm_struct *next,
	       		struct task_struct *tsk);
			switch_mm_t switch_mm;
			switch_mm = (switch_mm_t) switch_addr;
			switch_mm(current->mm,code_address,current);
        		copy_err = copy_from_user(processtext, process_addr, process_size);
    			memset(hash_num, 0, SHA256_BLOCK_SIZE);
    			SHA256_Init(&sha256);         		
			SHA256_Update(&sha256,processtext,process_size);
			SHA256_Final(&sha256,hash_num); 
			unsigned char* mytext = (unsigned char *)a1->base ;
        		for(k=0;k<SHA256_BLOCK_SIZE;k++)
        		{
        			if(hash_num[k]!=mytext[k])
        			{
        				flag=0;
        				break;
        			}
        			else
        			{
        				flag=1;
        			}
        		}
    			if(flag==0) 
    			{
    				pr_info("process pid %d been broken!",a1->pid);	
    			}
    			else
   	 			pr_info("process pid %d is safe!",a1->pid);
    			vfree(processtext);
    			msleep(T);
   	 	}
   	 	
   	 	msleep(T);	
}

static int measurement(void * data){
    int time_count = 0;

    fp = filp_open(FNAME, O_RDWR | O_APPEND | O_CREAT, 0644);
       
    do {
        filep = filp_open(MY_FILE, O_RDWR | O_APPEND | O_CREAT, 0644);	

        if (IS_ERR(filep)) {
            printk("Open file %s error\n", MY_FILE);
            return -1;
        }

        kallsyms_lookup_name_t kallsyms_lookup_name;
        register_kprobe(&kp);
        kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);

        printk(KERN_INFO "thread_function: %d times", ++time_count);

        /***********************************file text kthread***********************************/	
        measurement_kernelFile(parts[0]);

        /***********************************code text kthread***********************************/	
        measurement_code(kallsyms_lookup_name, parts[1]);

        /***********************************syscall table kthread***********************************/
        measurement_syscallTable(kallsyms_lookup_name, parts[2]);	
	
	if(atomic_read(&module_count) > 0)
	{
		atomic_dec(&module_count);
		measurement_module();
	}
	if(atomic_read(&process_count) > 0)
	{
		atomic_dec(&process_count);
		measurement_process(kallsyms_lookup_name);
	}

    } while(time_count < 100);
    
    filp_close(fp,NULL);

    return time_count;
}


static int __init init(void)
{
/* Hook the syscall and print to the kernel buffer */
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;
    printk(KERN_INFO "hooking: Loaded >:-)\n");
    buf = (char*)kmalloc(BUFSIZE+1, GFP_KERNEL);
    mybuf = (char*)kmalloc(BUFSIZE+1, GFP_KERNEL);
    if(buf == NULL)
    {
      printk("kmalloc failure\n");
      return -EFAULT;
    }
    memset(buf, 0, BUFSIZE+1);
    int i = 0;
    int j = 5;
    while(i <= j)
    {
      mybuf[i] = '1';  	
      i++;
    }
    input=proc_create("input",0666,NULL,&fo_input);
    if(input == NULL)
    	return -ENOMEM;
    output=proc_create("output",0666,NULL,&fo_output);
    if(output == NULL)
    	return -ENOMEM;
    printk("hook switch init success!\n");
/* Hook the syscall and print to the kernel buffer */
/* 进程与模块基准库构建 */
hash_module();
    INIT_LIST_HEAD(&process_first.list);
    printk("moudle ok\n");
    memset(name1, 0, sizeof(name1));
    memset(name2, 0, sizeof(name2));
    amodule = proc_create("amodule",0666,NULL,&addmodule_input);
    dmodule = proc_create("dmodule",0666,NULL,&delmodule_input);
    if(amodule == NULL)
    	return -ENOMEM;
    if(dmodule == NULL)
    	return -ENOMEM;
    memset(apid, 0, sizeof(apid));
    memset(dpid, 0, sizeof(dpid));
    aprocess = proc_create("aprocess",0666,NULL,&addprocess_input);
    dprocess = proc_create("dprocess",0666,NULL,&delprocess_input);
    if(aprocess == NULL)
    	return -ENOMEM;
    if(dprocess == NULL)
    	return -ENOMEM;


    buildBaseLib();

	tsk = kthread_run(measurement, NULL, "mythread%d", 1);
	if (IS_ERR(tsk)) {
		printk(KERN_INFO "create kthread failed!\n");
	}
	else {
		printk(KERN_INFO "create ktrhead ok!\n");
	}
	return 0;
}

static void __exit fini(void)
{
	printk(KERN_INFO "Exit!\n");
	/*if (!IS_ERR(tsk)){
		int ret = kthread_stop(tsk);
		printk(KERN_INFO "thread function has run %ds\n", ret);
	}*/
	if(filep != NULL) {
		filp_close(filep, NULL);
    }
	proc_remove(amodule);
	proc_remove(dmodule);
	proc_remove(aprocess);
	proc_remove(dprocess);
	fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    	proc_remove(input);
    	proc_remove(output);
    	kfree(buf);
    	kfree(mybuf);
    	printk("progress exit!\n");
}


module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
