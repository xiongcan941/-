#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>   
#include <linux/string.h>
#include "SHA256.h"
#include "config.h"
#include <linux/kernel.h>
#include <linux/netdevice.h>

#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mm_types.h>
#include <linux/mm.h>	
#include <linux/list.h>	

static struct kprobe kp1 = {
    .symbol_name = "kallsyms_lookup_name"
};

DEFINE_MUTEX(mymodule_mutex);

struct benchmark{
	char name[MODULE_NAME_LEN];
	/* benchmark address */
	void *base;
	struct module_layout module_lay;
	/* Member of list of modules */
	struct list_head list;
}____cacheline_aligned;

SHA256_CTX sha256;
//表头
struct benchmark first;
EXPORT_SYMBOL(first);
static struct list_head *moduless;
unsigned char *module_text = NULL;
unsigned char *moduletext = NULL;
unsigned char hash_num[32];


void hash_module(void){
	module_text = (unsigned char *)vzalloc(SHA256_BLOCK_SIZE);
        struct module *mod;
        struct benchmark *a;
        mod = THIS_MODULE;
        INIT_LIST_HEAD(&first.list);
        a = (struct benchmark *)vzalloc(sizeof(typeof(*a)));
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
	     module_text[k] = hash_num[k]; 
	}
	strcpy(a->name,mod->name);
	a->base = module_text;
	a->module_lay = mod->core_layout;
	list_add_tail(&a->list,&first.list);	
	vfree(moduletext);
}

void addhash_module(char name[]){
	module_text = (unsigned char *)vzalloc(SHA256_BLOCK_SIZE);
        struct module *mod;
        struct benchmark *a;
        struct benchmark b;
        typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp1);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp1.addr;
	unregister_kprobe(&kp1);
	moduless = (struct list_head *)kallsyms_lookup_name("modules");
        list_for_each_entry_rcu(mod, moduless, list)
        {
            if(strcmp(name,mod->name) == 0)
            {
            	printk("module name is:%s\n",name);
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
	     		module_text[k] = hash_num[k]; 
	     		
	  	}
	        a->base = module_text;
	        strcpy(a->name,mod->name);
	        a->module_lay = mod->core_layout;
		list_add_tail_rcu(&a->list,&first.list);
		vfree(moduletext);
		break;
	    }
	}
}

void delhash_module(char name[]){
	struct benchmark *mod;
	list_for_each_entry_rcu(mod,&first.list,list)
	{
		if(strcmp(name,mod->name) == 0)
		{
			vfree(mod->base);
			list_del_rcu(&mod->list);
			vfree(mod);
			break;
		}
	}
}
