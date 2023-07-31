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
#include "bitmap.h"
#include <linux/kernel.h>
#include <linux/netdevice.h>

#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mm_types.h>
#include <linux/mm.h>	
#include <linux/list.h>	

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

static bitmap_t module_frames_map;
static unsigned int bitarray[1024 / 32];

DEFINE_MUTEX(mymodule_mutex);

struct benchmark{
	char name[MODULE_NAME_LEN];
	/* benchmark address */
	void *base;
	struct module_layout module_lay;
	/* Member of list of modules */
	struct list_head list;
	int frame;
}____cacheline_aligned;

SHA256_CTX sha256;
//表头
struct benchmark first;
EXPORT_SYMBOL(first);
static struct list_head *moduless;
unsigned char module_text[1024][32] ;
unsigned char *moduletext = NULL;
unsigned char hash_num[32];

void init_paging(void) {
	int i = 0;
  	// Initialize module_frames_map. 
  	for (i = 0; i < 1024 / 32; i++) {
    		bitarray[i] = 0xFFFFFFFF;
  	}
  	module_frames_map = bitmap_create(bitarray, 1024 / 32);
}

int allocate_module_frame(void) {
  	mutex_lock(&mymodule_mutex);
  	unsigned int frame;
  	if (!bitmap_allocate_first_free(&module_frames_map, &frame)) {
    		mutex_unlock(&mymodule_mutex);
    		return -1;
  	}
  	mutex_unlock(&mymodule_mutex);
  	return (int)frame;
}

void release_module_frame(unsigned int frame) {
  	mutex_lock(&mymodule_mutex);
  	bitmap_clear_bit(&module_frames_map, frame);
  	mutex_unlock(&mymodule_mutex);
}

void hash_module(void){
	int num = allocate_module_frame();
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
	     module_text[num][k] = hash_num[k]; 	
	}
	strcpy(a->name,mod->name);
	a->base = &module_text[num];
	a->frame = num;
	a->module_lay = mod->core_layout;
	list_add_tail(&a->list,&first.list);	
	vfree(moduletext);
}

void addhash_module(char name[]){
	int num = allocate_module_frame();
	if(num == -1)
		return;
        struct module *mod;
        struct benchmark *a;
        struct benchmark b;
        typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
	moduless = (struct list_head *)kallsyms_lookup_name("modules");
        list_for_each_entry(mod, moduless, list)
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
	     		module_text[num][k] = hash_num[k]; 
	     		
	  	}
	        a->base = &module_text[num];
	        strcpy(a->name,mod->name);
	        a->frame = num;
	        a->module_lay = mod->core_layout;
		list_add_tail(&a->list,&first.list);
		vfree(moduletext);
		break;
	    }
	}
}

void delhash_module(char name[]){
	struct benchmark *mod;
	list_for_each_entry(mod,&first.list,list)
	{
		if(strcmp(name,mod->name) == 0)
		{
			list_del(&mod->list);
			release_module_frame(mod->frame);
			vfree(mod);
			break;
		}
	}
}
