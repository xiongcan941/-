#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "../SHA256.h"
#include "../config.h"
#include <linux/netdevice.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/kthread.h>

// #define MY_FILE "/home/mzr/Learn_Linux_kernel/Benchmark_database_establishment/log.txt"

static char s[4096];
static struct task_struct *tsk;
unsigned char *systext = NULL;
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
unsigned long sys_size;
loff_t pos = 0;
loff_t w_pos = 0;

struct file * filep = NULL;
struct file * f = NULL;

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

unsigned char hash_num[32];
unsigned char hash_num_init[32];
bool flag=1;
size_t count;
struct file *fp = NULL;
unsigned char *plaintext = NULL;
void *buf;
SHA256_CTX sha256;	//用来计算sha256 hash值

struct benchmark{
	char name[MODULE_NAME_LEN];
	/* benchmark address */
	void *base;
	struct module_layout module_lay;
	/* Member of list of modules */
	struct list_head list;
	int frame;
}____cacheline_aligned;

struct process_benchmark{
	int pid;
	/* benchmark address */
	void *base;
	struct task_struct* process_task;
	/* Member of list of modules */
	struct list_head list;
	int frame;
}____cacheline_aligned;

extern int register_test_notifier(struct notifier_block*);
extern int unregister_test_notifier(struct notifier_block*);
extern struct benchmark first; 
extern struct process_benchmark process_first; 

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


void measurement_kernelFile(void){
    bool flag=1;
    int k = 0;

    long long start_time;
    long long end_time;
    start_time = ktime_get();

    fp = filp_open("/var/spool/cron/crontabs/root",O_RDWR | O_CREAT,0644);

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
    }

    if(flag==0) pr_info("kernel file text has been broken!");	
    if(flag==1) pr_info("kernel file text 1 is safe!");

    end_time = ktime_get();
    printk(KERN_INFO "end_time: %lld", end_time);

    char timeStr[66];
    getTime(start_time, end_time, timeStr);

    kernel_write(f, timeStr, 66, &w_pos);

    msleep(T);
}

void measurement_module(void){
    		bool flag=1;
    		int i = 0,j = 0,k = 0;
    		struct benchmark *module_head = &first;
        	struct benchmark *a1;
        	list_for_each_entry(a1, &module_head->list, list)
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
        	struct task_struct* task_address;
        	list_for_each_entry(a1, &process_head->list, list)
    		{
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

void measurement_code(int num, kallsyms_lookup_name_t kallsyms_lookup_name){
		
    int i = 0,j = 0,k = 0;

    unsigned long size;
    unsigned char *func_addr1 = (unsigned char *)kallsyms_lookup_name("_text");
    unsigned char *func_addr2= (unsigned char *)kallsyms_lookup_name("_etext");

    size=func_addr2-func_addr1;
    plaintext = (unsigned char *)vzalloc(size);

    for (k = 1; k<=num; k++){
        long long start_time;
        long long end_time;
        start_time = ktime_get();
        flag=1;

	plaintext = (unsigned char *)vzalloc(size);

        for (i, j=0; i<size && i<size/num*k; i++,j++) 
        {
            plaintext[j] = func_addr1[i];
        }
        
        memset(hash_num, 0, SHA256_BLOCK_SIZE);
        SHA256_Init(&sha256);         		
        SHA256_Update(&sha256,plaintext,size/num);
        SHA256_Final(&sha256,hash_num); 
        
        memset(hash_num_init, 0, SHA256_BLOCK_SIZE);
        buf = (void *)hash_num_init;
        kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);

        for(j=0;j<SHA256_BLOCK_SIZE;j++)
        {
            if(hash_num[j]!=hash_num_init[j])
            {
                flag=0;
                break;
            }
        }

        if(flag==0) pr_info("kernel code text %d has been broken!", k);	
        if(flag==1) pr_info("kernel code text %d is safe!", k);
        
        end_time = ktime_get();
        printk(KERN_INFO "end_time: %lld", end_time);

        char timeStr[66];
        getTime(start_time, end_time, timeStr);

        kernel_write(f, timeStr, 66, &w_pos);
        
	vfree(plaintext);

        msleep(T);
    }
}

void measurement_syscallTable(int num, kallsyms_lookup_name_t kallsyms_lookup_name){
    flag = 1;
    int i = 0;
    long long start_time;
    long long end_time;
    start_time = ktime_get();

    unsigned long *syscall_table= (unsigned long *)kallsyms_lookup_name("sys_call_table"); 
    unsigned char *syscall_table2=syscall_table[__NR_kill];
    sys_size=__NR_syscall_max;

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

    for(i=0;i<SHA256_BLOCK_SIZE;i++)
    {
         if(hash_num[i]!=hash_num_init[i]){
             flag=0;
             break;
         }
    }
    if(flag==0) pr_info("kernel syscall table has been broken!");	
    if(flag==1) pr_info("kernel syscall table is safe!");

    end_time = ktime_get();
    printk(KERN_INFO "end_time: %lld", end_time);

    char timeStr[66];
    getTime(start_time, end_time, timeStr);

    kernel_write(f, timeStr, 66, &w_pos);

    w_pos+=66;
    
    msleep(T);	
}

static int show1(struct notifier_block *this, unsigned long event, void *ptr)
{
                if(event == 1)
                {
                	measurement_module();
    		}
    		if(event == 2)
                {
                	measurement_module();
    		}
    		return 0;
}

static struct notifier_block test_notifier1 =
{
	.notifier_call = show1,
};

static int measurement(void * data){
    int time_count = 0;

//    char fname[] = "/root/DemoA/2.代码/DemoA—完整性度量模型/Benchmark_database_establishment/log_0630-50.log";

    f = filp_open(FNAME, O_RDWR | O_APPEND | O_CREAT, 0644);
       
    do {
        filep = filp_open(MY_FILE, O_RDWR | O_APPEND | O_CREAT, 0644);	

        if (IS_ERR(filep)) {
            printk("Open file %s error\n", MY_FILE);
            return -1;
        }

        typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
        kallsyms_lookup_name_t kallsyms_lookup_name;
        register_kprobe(&kp);
        kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);

        printk(KERN_INFO "thread_function: %d times", ++time_count);

        /***********************************file text kthread***********************************/	
        measurement_kernelFile();

        /***********************************code text kthread***********************************/	
        measurement_code(num, kallsyms_lookup_name);

        /***********************************syscall table kthread***********************************/
        measurement_syscallTable(num, kallsyms_lookup_name);
        measurement_module();
	measurement_process(kallsyms_lookup_name);
    } while(time_count < 100);
    
    filp_close(f,NULL);

    return time_count;
}

static int hello_init(void)
{
	int err = register_test_notifier(&test_notifier1);
        if (err)
	{
        	printk("register test_notifier1 error\n");
		return -1;
	}
	tsk = kthread_run(measurement, NULL, "mythread%d", 1);
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
	/*if (!IS_ERR(tsk)){
		int ret = kthread_stop(tsk);
		printk(KERN_INFO "thread function has run %ds\n", ret);
	}*/
	unregister_test_notifier(&test_notifier1);
	if(filep != NULL) {
		filp_close(filep, NULL);
    }
    printk("file close!\n");
}
 
module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("Dual BSD/GPL");

