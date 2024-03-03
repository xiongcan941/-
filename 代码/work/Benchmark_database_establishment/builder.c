#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>          //  copy_to_user() & copy_from_user
#include <linux/string.h>
#include "process.h"
#include <linux/kernel.h>
#include <linux/netdevice.h>

#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mm_types.h>
#include <linux/mm.h>		
#include <linux/proc_fs.h>

// #define MY_FILE "/home/mzr/Learn_Linux_kernel/Benchmark_database_establishment/log.txt"
static char s[4096];

// unsigned char buf1[10001];
loff_t pos = 0;
size_t count;
struct file *filep = NULL;
struct file *fp = NULL;

unsigned char *alltext = NULL;
unsigned char *systext = NULL;
unsigned char *buf[32];

static struct proc_dir_entry *amodule,*dmodule;
static char name1[56];
static char name2[56];
static struct proc_dir_entry *aprocess,*dprocess;
static int pid1;
static int pid2;
static char apid[4];
static char dpid[4];

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

static void hash_file(void){
    //  读取文件，设置pos为0
    fp =filp_open("/var/spool/cron/crontabs/root",O_RDWR | O_CREAT,0644);
    pos =0;
    kernel_read(fp,s,sizeof(s),&pos);
    filp_close(fp,NULL);
	unsigned char *input=s;

    SHA256_Init(&sha256);
	SHA256_Update(&sha256,input,strlen(input));
	SHA256_Final(&sha256,hash_num);
	pr_info("the file text :");	
	int ef;
	for(ef=0;ef<SHA256_BLOCK_SIZE;ef++)
  	{
	 	pr_info("0x%02x",hash_num[ef]);
  	}
    pr_info("\n");

    buf[0] = (unsigned char *)vzalloc(SHA256_BLOCK_SIZE);

    memcpy(buf[0],hash_num,SHA256_BLOCK_SIZE);
}

static void hash_kernelCode(int num){
    int i = 0,j = 0, k = 0, f=1;
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
	unsigned long size;
	unsigned char *func_addr1 = (unsigned char *)kallsyms_lookup_name("_text");
	unsigned char *func_addr2= (unsigned char *)kallsyms_lookup_name("_etext");
	
    size=func_addr2-func_addr1;
	pr_info("%d", size);
//	alltext = (unsigned char *)vzalloc(size);
    for(f=1; f<=num; f++){
        j = 0;
        
	alltext = (unsigned char *)vzalloc(size);
       	
	for (i ;i<size && i<size/num*f; i++) 
        {   
            alltext[j] = func_addr1[i];
            j++;
        }
        memset(hash_num, 0, SHA256_BLOCK_SIZE);
        SHA256_Init(&sha256);
        SHA256_Update(&sha256,alltext,size/num);
        SHA256_Final(&sha256,hash_num);

        pr_info("the code text %d:", f);	
        for(k=0;k<SHA256_BLOCK_SIZE;k++)
        {
            pr_info("0x%02x",hash_num[k]);
        }
        pr_info("\n");
            
        buf[f] = (unsigned char *)vzalloc(SHA256_BLOCK_SIZE);

        memcpy(buf[f],hash_num,SHA256_BLOCK_SIZE);

	vfree(alltext);
    }
}

static void hash_syscall(int num){
    unsigned long sys_size;
    int i=0, k=0;
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
    unsigned long *syscall_table= (unsigned long *)kallsyms_lookup_name("sys_call_table");  
	unsigned char *syscall_table2=syscall_table[__NR_kill];

    sys_size=__NR_syscall_max;
//	pr_info("%d", __NR_syscall_max);

	systext = (unsigned char *)vzalloc(sys_size);
    for (i = 0; i < sys_size; i++) 
    {
        systext[i] = syscall_table[i];
    }
    memset(hash_num, 0, SHA256_BLOCK_SIZE);
    SHA256_Init(&sha256);
	SHA256_Update(&sha256,systext,sys_size);
	SHA256_Final(&sha256,hash_num);

	pr_info("the syscall text :");	
    for(k=0;k<SHA256_BLOCK_SIZE;k++)
    {
        pr_info("0x%02x",hash_num[k]);
    }
    pr_info("\n");

    buf[num+1] = (unsigned char *)vzalloc(SHA256_BLOCK_SIZE);
        
    memcpy(buf[num+1], hash_num, SHA256_BLOCK_SIZE);

    vfree(systext);
}

void hash_task(int pid, int num){
	int i = 0;
	unsigned char *plaintext = NULL;

	/*
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
	unsigned long size;
	unsigned char *func_addr1 = (unsigned char *)kallsyms_lookup_name("_text");
	unsigned char *func_addr2= (unsigned char *)kallsyms_lookup_name("_etext");
	unsigned long *syscall_table= (unsigned long *)kallsyms_lookup_name("sys_call_table"); 
	unsigned char *syscall_table2=syscall_table[__NR_kill];
	*/

	struct pid * kpid=find_get_pid(pid);           //获取当前进程的描述符信息
    printk("current pid is:%d\n", pid);

    struct task_struct * task=pid_task(kpid, PIDTYPE_PID); //获取进程的任务描述符信息
    struct mm_struct * mm_task=my_get_task_mm(task); 	

	unsigned long *start_code = (unsigned long*)mm_task->start_code;

	unsigned long size_code;

	size_code = mm_task->end_code - mm_task->start_code;

	plaintext = (unsigned char *)vzalloc(size_code);
    
	copy_to_user(plaintext, start_code, size_code);
    memset(hash_num, 0, SHA256_BLOCK_SIZE);
	SHA256_Init(&sha256);
	SHA256_Update(&sha256,plaintext,size_code);
	SHA256_Final(&sha256,hash_num);
		
	for(i=0;i<SHA256_BLOCK_SIZE;i++)
	{
		pr_info("0x%02x",hash_num[i]);
	}

	buf[num+2] = (unsigned char *)vzalloc(SHA256_BLOCK_SIZE);
        
    memcpy(buf[num+2], hash_num, SHA256_BLOCK_SIZE);
}

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
  printk("%d\n",pid);
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
  delhash_process(pid2);
  return sizeof(pid2);
}

static struct proc_ops delprocess_input = 
{
  .proc_write = delprocess,
};

static int __init init(void)
{
    int k = 1;
    printk("Hello, I'm the module that intends to write message to file.\n");
    
    filep = filp_open(MY_FILE, O_RDWR | O_APPEND | O_CREAT, 0644);
    if (IS_ERR(filep)) {
        printk("Open file %s error\n", MY_FILE);
        return -1;
    }
	
    hash_file();

    //  将hash结果写入到文件中，这里可以考虑建立数组
	kernel_write(filep, buf[0], SHA256_BLOCK_SIZE, &pos);

/*************the code text hash start******************/

    hash_kernelCode(num);

    for (k=1; k<=num; k++){
    	kernel_write(filep, buf[k], SHA256_BLOCK_SIZE, &pos);
    }
//    kernel_write(filep, buf[1], SHA256_BLOCK_SIZE*num, &pos);
/*************the code text hash end********************/

/*************the syscall hash start***********************/

	hash_syscall(num);
  
	kernel_write(filep, buf[num+1], SHA256_BLOCK_SIZE, &pos);
/*************the syscall hash end***********************/

    hash_task(current->pid, num);
    //  hash_task(pid, num);

    kernel_write(filep, buf[num+2], SHA256_BLOCK_SIZE, &pos);
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
    return 0;
}

static void __exit fini(void)
{
	if(filep != NULL) 
	{
		filp_close(filep, NULL);				 
	}
	printk("write success!\n");
	proc_remove(amodule);
	proc_remove(dmodule);
	proc_remove(aprocess);
	proc_remove(dprocess);
}

module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");
