#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "SHA256.h"
#include <linux/netdevice.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/notifier.h>
#include <linux/list.h>


#define MY_FILE "/home/xc/Benchmark_database_establishment/log.txt"
#define MY_FILE1 "/home/xc/Benchmark_database_establishment/log1.txt"
static char s[4096];
static struct task_struct *tsk;
static struct list_head *modules;
unsigned char *func_addr1;
unsigned char *func_addr2;
unsigned long *syscall_table;
unsigned char *systext = NULL;
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
unsigned long sys_size;

typedef struct benchmark{
	/* jizhunku address */
	void *base;
	/* Member of list of modules */
	struct list_head list;
}____cacheline_aligned;

loff_t pos = 0;

struct file *filep = NULL;

unsigned char hash_num[32];
unsigned char hash_num_init[32];

bool flag=true;
size_t count;
struct file *fp = NULL;
unsigned char *plaintext = NULL;
void *buf;
static struct task_struct *tsk1;
char s1[4096];
		

unsigned char *systext1 = NULL;
unsigned char *moduletext = NULL;	
unsigned long sys_size1;

loff_t pos1 = 0;

struct file *filep1 = NULL;
struct file *filep2 = NULL;

unsigned char hash_num1[32];
unsigned char hash_num_init1[32];
		
bool flag1=true;
size_t count1;
struct file *fp1 = NULL;
unsigned char *plaintext1 = NULL;
void *buf1;
SHA256_CTX sha256;	//鐢ㄦ潵璁＄畻sha256 hash鍊?

extern struct list_head myhead; 
static int show1(struct notifier_block *this, unsigned long event, void *ptr)
{
                if(event == 1){
    		int i = 0,j = 0,k = 0;
    		struct module *mod;
        	struct module *mymodule = ptr;
        	flag1=1;
        	
        	struct benchmark *a1;
        	struct benchmark *address = list_entry_rcu(myhead.next, typeof(*a1), list);
		preempt_disable();
        	list_for_each_entry_rcu(mod, modules, list)
    		{
    		struct module_layout core_address = mod->core_layout;
    		unsigned char *module_addr = (unsigned char *) core_address.base;
    		unsigned int module_size = core_address.text_size;
/***********************************module kthread***********************************/
		moduletext = (unsigned char *)vzalloc(module_size);
		for (i=0; i < module_size; i++) 
    		{
    			moduletext[i] = module_addr[i];
    		}
    		memset(hash_num1, 0, SHA256_BLOCK_SIZE);
    		SHA256_Init(&sha256);         		
		SHA256_Update(&sha256,moduletext,module_size);
		SHA256_Final(&sha256,hash_num1); 
		
		unsigned char* mytext = (unsigned char *)address->base ;
        	for(k=0;k<SHA256_BLOCK_SIZE;k++)
        	{
        		if(hash_num1[k]!=mytext[k])
        		{
        			flag1=0;
        			break;
        		}
        		else
        		{
        			flag1=1;
        		}
        	}
    		if(flag1==0) {pr_info("hook-kernel module been broken!");	break;}
    		address = list_entry_rcu(address->list.next,typeof(*a1),list);
   	 	}
		preempt_enable();
   	 	if(flag1==1) pr_info("hook-kernel module is safe!");
   	 	}
		return 0;
}
static int thread_function(void *data)
{
	int time_count = 0;
	do {
		printk(KERN_INFO "thread_function: %d times", ++time_count);
		
                	filep = filp_open(MY_FILE, O_RDWR | O_APPEND | O_CREAT, 0644);
        	

        	if (IS_ERR(filep)) {
                	printk("Open file %s error\n", MY_FILE);
                	return -1;
        	}
        	int i = 0,j = 0,k = 0;
        	unsigned long size;
    		unsigned char *syscall_table2=syscall_table[__NR_kill];
    		sys_size=__NR_syscall_max;
    		size=func_addr2-func_addr1;
    		plaintext = (unsigned char *)vzalloc(size);
 /***********************************file text kthread***********************************/	   		
    		fp =filp_open("/var/spool/cron/crontabs/root",O_RDWR | O_CREAT,0644);
        	pos =0;
        	kernel_read(fp,s,sizeof(s),&pos);
        	filp_close(fp,NULL);
		unsigned char *input=s;
	

    		pos=0;
        	SHA256_Init(&sha256);
		SHA256_Update(&sha256,input,strlen(input));
		SHA256_Final(&sha256,hash_num);
		memset(hash_num_init, 0, SHA256_BLOCK_SIZE);
		buf = (void *)hash_num_init;
        	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
        	for(k=0;k<SHA256_BLOCK_SIZE;k++)
        	{
        		if(hash_num[k]!=hash_num_init[k])
        		{
        			flag=0;
        			break;
        		}
        		else
        		{
        			flag=1;
        		}
        	}
    		if(flag==0) pr_info("kernel file text has been broken!");	
   	 	if(flag==1) pr_info("kernel file text 1 is safe!");
   	 	msleep(2000);
/***********************************code text 1 kthread***********************************/	
    		flag=1;
    		for (i = 0; i < size; i++) 
    		{
    			plaintext[j] = func_addr1[i];
    			j++;
    		}
    		memset(hash_num, 0, SHA256_BLOCK_SIZE);
    		SHA256_Init(&sha256);         		
		SHA256_Update(&sha256,plaintext,size);
		SHA256_Final(&sha256,hash_num); 
		
		
		
		memset(hash_num_init, 0, SHA256_BLOCK_SIZE);
		buf = (void *)hash_num_init;
        	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
        	for(k=0;k<SHA256_BLOCK_SIZE;k++)
        	{
        		if(hash_num[k]!=hash_num_init[k])
        		{
        			flag=0;
        			break;
        		}
        		else
        		{
        			flag=1;
        		}
        	}
    		if(flag==0) pr_info("kernel has been broken!");	
   	 	if(flag==1) pr_info("kernel is safe!");
   	 	msleep(2000);
/***********************************syscall table kthread***********************************/
		flag=1;
		systext = (unsigned char *)vzalloc(sys_size);
		for (i=0; i < sys_size; i++) 
    		{
    			systext[i] = syscall_table[i];
    			
    		}
    		memset(hash_num, 0, SHA256_BLOCK_SIZE);
    		SHA256_Init(&sha256);         		
		SHA256_Update(&sha256,systext,sys_size);
		SHA256_Final(&sha256,hash_num); 
		
		
		memset(hash_num_init, 0, SHA256_BLOCK_SIZE);
		buf = (void *)hash_num_init;
        	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
        	for(k=0;k<SHA256_BLOCK_SIZE;k++)
        	{
        		if(hash_num[k]!=hash_num_init[k])
        		{
        			flag=0;
        			break;
        		}
        		else
        		{
        			flag=1;
        		}
        	}
    		if(flag==0) pr_info("kernel syscall table has been broken!");	
   	 	if(flag==1) pr_info("kernel syscall table is safe!");
   	 	
		msleep(4000);		
		
		flag1=1;
		struct benchmark *a1;
		struct benchmark *address = list_entry_rcu(myhead.next, typeof(*a1), list);
        	struct module *mod;
		preempt_disable();
		list_for_each_entry_rcu(mod, modules, list)
    		{
    		struct module_layout core_address = mod->core_layout;
    		unsigned char *module_addr = (unsigned char *) core_address.base;
    		unsigned int module_size = core_address.text_size;
/***********************************module kthread***********************************/
		moduletext = (unsigned char *)vzalloc(module_size);
		for (i=0; i < module_size; i++) 
    		{
    			moduletext[i] = module_addr[i];
    		}
    		memset(hash_num1, 0, SHA256_BLOCK_SIZE);
    		SHA256_Init(&sha256);         		
		SHA256_Update(&sha256,moduletext,module_size);
		SHA256_Final(&sha256,hash_num1); 
		
		unsigned char* mytext = (unsigned char *)address->base ;
		
        	for(k=0;k<SHA256_BLOCK_SIZE;k++)
        	{
        		if(mytext[k] == hash_num1[k])
        		{
        			flag = 1;
        		}else{
        			flag = 0;
        			break;
        		}
        	}
        	if(flag == 0)
        	{
        		pr_info("module has benn broken!");
        		break;
		}
    		address = list_entry_rcu(address->list.next,typeof(*a1),list);
   	 	}
		preempt_enable();
   	 	if(flag == 1)
   	 	{
   	 		pr_info("module is safe!");
   	 	}
		
	}while(!kthread_should_stop() && time_count<=60);
	return time_count;
}
 

extern int register_test_notifier(struct notifier_block*);
extern int unregister_test_notifier(struct notifier_block*);

static struct notifier_block test_notifier1 =
{
.notifier_call = show1,
};

static int hello_init(void)
{
        int err;
	printk(KERN_INFO "Hello, world!\n");
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    	kallsyms_lookup_name_t kallsyms_lookup_name;
    		
    	register_kprobe(&kp);
    	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    	unregister_kprobe(&kp);
    	func_addr1 = (unsigned char *)kallsyms_lookup_name("_text");
    	func_addr2= (unsigned char *)kallsyms_lookup_name("_etext");
    	syscall_table= (unsigned long *)kallsyms_lookup_name("sys_call_table"); 
	modules = (struct list_head *)kallsyms_lookup_name("modules");  
        err = register_test_notifier(&test_notifier1);
        if (err)
	{
         printk("register test_notifier1 error\n");
	 return -1;
	}
	tsk = kthread_run(thread_function, NULL, "mythread%d", 1);
	if (IS_ERR(tsk)) {
		printk(KERN_INFO "create kthread failed!\n");
	}
	else {
		printk(KERN_INFO "create ktrhead ok!\n");
	}
	return 0;
}
 
static void hello_exit(void)
{
	printk(KERN_INFO "Hello, exit!\n");
	unregister_test_notifier(&test_notifier1);
	/*if (!IS_ERR(tsk)){
		int ret = kthread_stop(tsk);
		printk(KERN_INFO "thread function has run %ds\n", ret);
	}*/
	if(filep != NULL) {
                filp_close(filep, NULL);
        }
        printk("file close!\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("GPL");

