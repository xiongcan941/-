#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "SHA256.h"
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/list.h>
#include <linux/cache.h>

#define MY_FILE "/home/xc/Benchmark_database_establishment/log.txt"
static struct list_head *moduless;
static char s[4096];
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

struct benchmark{
	char name[MODULE_NAME_LEN];
	/* jizhunku address */
	void *base;
	/* Member of list of modules */
	struct list_head list;
}____cacheline_aligned;

unsigned char buf1[10001];
size_t count;
loff_t pos = 0;
struct file *filep = NULL;
struct file *filep1 = NULL;
struct file *fp = NULL;
unsigned char hash_num[32];
unsigned char module_text[1000][32] ;
unsigned char *alltext = NULL;
unsigned char *systext = NULL;
unsigned char *moduletext = NULL;
void *buf;
unsigned int num ;
static struct list_head myhead; 
SHA256_CTX sha256;
DEFINE_MUTEX(mymodule_mutex);
extern int register_test_notifier(struct notifier_block*);
extern int unregister_test_notifier(struct notifier_block*);

static int show(struct notifier_block *this, unsigned long event, void *ptr)
{
	if(event == 11){
	num = 0;
	INIT_LIST_HEAD(&myhead);
        struct module *mod;
        struct module *mymodule = ptr;
        struct benchmark *a;
        struct benchmark b;
	mutex_lock(&mymodule_mutex);
        list_for_each_entry_rcu(mod, moduless, list)
        {
        	a = (struct benchmark *)vzalloc(sizeof(b));
    		struct module_layout core_address = mod->core_layout;
    		unsigned char *module_addr = (unsigned char *) core_address.base;
    		unsigned int module_size = core_address.text_size;
		moduletext = (unsigned char *)vzalloc(module_size);
		int i,k;
        	for (i = 0; i < module_size; i++) 
    		{
    			moduletext[i] = module_addr[i];
    		}
    		memset(hash_num, 0, SHA256_BLOCK_SIZE);
    		SHA256_Init(&sha256);
		SHA256_Update(&sha256,moduletext,module_size);
		SHA256_Final(&sha256,hash_num);
		
    		for(k=0;k<SHA256_BLOCK_SIZE;k++)
	  	{
	     		module_text[num][k] = hash_num[k]; 
	     		
	  	}
	        a->base = &module_text[num];
	        strcpy(a->name,mod->name);
	        num++;
		list_add_tail(&a->list,&myhead);
	}
	synchronize_rcu();
	mutex_unlock(&mymodule_mutex);
	}
	else if(event == 12)
	{
		struct benchmark * bcm;
		struct module *mymodule = ptr;
		char *name1 = mymodule->name; 
		mutex_lock(&mymodule_mutex);
		list_for_each_entry_rcu(bcm,&myhead,list)
		{
			if(strcmp(name1,bcm->name)==0)
			{
				list_del_rcu(&bcm->list);
			}
		}
		synchronize_rcu();
		mutex_unlock(&mymodule_mutex);
	}
	return 0;
}

static struct notifier_block test_notifier2 =
{
	.notifier_call = show,
};


static int __init init(void)
{
        printk("Hello, I'm the module that intends to write message to file.\n");
        
	fp =filp_open("/var/spool/cron/crontabs/root",O_RDWR | O_CREAT,0644);
        pos =0;
        kernel_read(fp,s,sizeof(s),&pos);
        filp_close(fp,NULL);
	unsigned char *input=s;
	
        filep = filp_open(MY_FILE, O_RDWR | O_APPEND | O_CREAT, 0644);
        if (IS_ERR(filep)) {
                printk("Open file %s error\n", MY_FILE);
                return -1;
        }
        SHA256_Init(&sha256);
	SHA256_Update(&sha256,input,strlen(input));
	SHA256_Final(&sha256,hash_num);
	pr_info("the file text :");	
	int ef;
    	for(ef=0;ef<SHA256_BLOCK_SIZE;ef++)
	  	{
	     	pr_info("0x%02x",hash_num[ef]);
	  	}
	        
    	buf = (void *)hash_num;
  
	kernel_write(filep, buf, SHA256_BLOCK_SIZE, &pos);
	pr_info("\n");
	
        
        int i = 0,j = 0, k = 0;
        typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    	kallsyms_lookup_name_t kallsyms_lookup_name;
    	register_kprobe(&kp);
    	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    	unregister_kprobe(&kp);
    	unsigned long size;
    	unsigned long sys_size;
    	unsigned char *func_addr1 = (unsigned char *)kallsyms_lookup_name("_text");
    	unsigned char *func_addr2= (unsigned char *)kallsyms_lookup_name("_etext");
    	unsigned long *syscall_table= (unsigned long *)kallsyms_lookup_name("sys_call_table");  
    	moduless = (struct list_head *)kallsyms_lookup_name("modules");  
    	unsigned char *syscall_table2=syscall_table[__NR_kill];
    	
    	size=func_addr2-func_addr1;
    	sys_size=__NR_syscall_max;
/*************the code text 1 hash start******************/
       alltext = (unsigned char *)vzalloc(size);
       for (i = 0; i < size; i++) 
    	{
    		alltext[i] = func_addr1[i];
    	}
    	memset(hash_num, 0, SHA256_BLOCK_SIZE);
    	SHA256_Init(&sha256);
	SHA256_Update(&sha256,alltext,size);
	SHA256_Final(&sha256,hash_num);

	pr_info("the code text 1:");	
    	for(k=0;k<SHA256_BLOCK_SIZE;k++)
	  	{
	     	pr_info("0x%02x",hash_num[k]);
	  	}
	        
    	buf = (void *)hash_num;
  
	kernel_write(filep, buf, SHA256_BLOCK_SIZE, &pos);
	pr_info("\n");
/*************the code text 1 hash end********************/

/*************the syscall hash start***********************/
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
	        
    	buf = (void *)hash_num;
  
	kernel_write(filep, buf, SHA256_BLOCK_SIZE, &pos);
	pr_info("\n");
	
	int err;
	err = register_test_notifier(&test_notifier2);
/*************read the code text hash start***************
	buf = (void *)buf1;
	pos=0;
	
	pr_info("read the code text 1:");	
	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
	for(i=0;i<SHA256_BLOCK_SIZE;i++)
		{
	      		pr_info("0x%02x",buf1[i]);
	        }
	memset(buf1, 0, SHA256_BLOCK_SIZE);
	pr_info("\n");
	buf = (void *)buf1;
	pr_info("read the code text 2:");
	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
	for(i=0;i<SHA256_BLOCK_SIZE;i++)
		{
	      		pr_info("0x%02x",buf1[i]);
	        }
	memset(buf1, 0, SHA256_BLOCK_SIZE);
	pr_info("\n");
	buf = (void *)buf1;
	pr_info("read the code text 3:");
	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
	for(i=0;i<SHA256_BLOCK_SIZE;i++)
		{
	      		pr_info("0x%02x",buf1[i]);
	        }
	        memset(buf1, 0, SHA256_BLOCK_SIZE);
	pr_info("\n");
	buf = (void *)buf1;
	pr_info("read the code text 4:");
	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
	for(i=0;i<SHA256_BLOCK_SIZE;i++)
		{
	      		pr_info("0x%02x",buf1[i]);
	        }
	        memset(buf1, 0, SHA256_BLOCK_SIZE);
	pr_info("\n");
	buf = (void *)buf1;
	pr_info("read the code text 5:");
	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
	for(i=0;i<SHA256_BLOCK_SIZE;i++)
		{
	      		pr_info("0x%02x",buf1[i]);
	        }
	        memset(buf1, 0, SHA256_BLOCK_SIZE);
	pr_info("\n");
	buf = (void *)buf1;
	pr_info("read the code text 6:");
	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
	for(i=0;i<SHA256_BLOCK_SIZE;i++)
		{
	      		pr_info("0x%02x",buf1[i]);
	        }
       
        memset(buf1, 0, SHA256_BLOCK_SIZE);
	pr_info("\n");
	buf = (void *)buf1;
	pr_info("read the code text 7:");
	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
	for(i=0;i<SHA256_BLOCK_SIZE;i++)
		{
	      		pr_info("0x%02x",buf1[i]);
	        }
	        memset(buf1, 0, SHA256_BLOCK_SIZE);
	pr_info("\n");
	buf = (void *)buf1;
	pr_info("read the code text 8:");
	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
	for(i=0;i<SHA256_BLOCK_SIZE;i++)
		{
	      		pr_info("0x%02x",buf1[i]);
	        }
	        memset(buf1, 0, SHA256_BLOCK_SIZE);
	pr_info("\n");
	buf = (void *)buf1;
	pr_info("read the code text 9:");
	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
	for(i=0;i<SHA256_BLOCK_SIZE;i++)
		{
	      		pr_info("0x%02x",buf1[i]);
	        }
	        memset(buf1, 0, SHA256_BLOCK_SIZE);
	pr_info("\n");
	buf = (void *)buf1;
	pr_info("read the code text 10:");
	kernel_read(filep, buf, SHA256_BLOCK_SIZE, &pos);
	for(i=0;i<SHA256_BLOCK_SIZE;i++)
		{
	      		pr_info("0x%02x",buf1[i]);
	        }
	        memset(buf1, 0, SHA256_BLOCK_SIZE);
	pr_info("\n");
	buf = (void *)buf1;

************read the code text hash end****************/
 return 0;
}


static void __exit fini(void)
{
        
unregister_test_notifier(&test_notifier2);
       if(filep != NULL) {
                filp_close(filep, NULL);
        }
        printk("write success!\n");
}

EXPORT_SYMBOL(myhead);
module_init(init);
module_exit(fini);
MODULE_LICENSE("GPL");



