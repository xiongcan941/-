#include <linux/init.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>   
#include <linux/string.h>
#include "module.h"
#include <linux/kernel.h>
#include <linux/netdevice.h>

#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/mm_types.h>
#include <linux/mm.h>	
#include <linux/list.h>	
#include <linux/signal.h>	

DEFINE_MUTEX(myprocess_mutex);

struct process_benchmark{
	int pid;
	/* benchmark address */
	void *base;
	struct task_struct* process_task;
	/* Member of list of modules */
	struct list_head list;
}____cacheline_aligned;

//表头
struct process_benchmark process_first;
EXPORT_SYMBOL(process_first);
unsigned char *process_text ;
unsigned char *processtext = NULL;
unsigned char process_hash_num[32];

void addhash_process(int pid){
	unsigned long copy_err;
	process_text = (unsigned char *)vzalloc(SHA256_BLOCK_SIZE);
        struct task_struct *proc;
        struct process_benchmark *a;
        struct process_benchmark b;
        typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
	unregister_kprobe(&kp);
	unsigned char *switch_addr = (unsigned char *)kallsyms_lookup_name("switch_mm");
	typedef void (*switch_mm_t)(struct mm_struct *prev, struct mm_struct *next,
	       struct task_struct *tsk);
	switch_mm_t switch_mm;
	switch_mm = (switch_mm_t) switch_addr;
        for_each_process(proc)
        {
            if(pid == proc->pid)
            {
            	printk("add process:%d\n",proc->pid);
        	a = (struct process_benchmark *)vzalloc(sizeof(b));
    		struct mm_struct* code_address = proc->mm;
    		unsigned long* process_addr = (unsigned long *) code_address->start_code;
    		unsigned long process_size = code_address->end_code - code_address->start_code;
		processtext = (unsigned char *)vzalloc(process_size);
		int i,k;
		unsigned long cr3_address;
  		asm volatile("mov %%cr3, %0" : "=r" (cr3_address));
		printk("before switch,cr3 is: %lu\n",cr3_address);
		switch_mm(current->mm,proc->mm,current);
		asm volatile("mov %%cr3, %0" : "=r" (cr3_address));
		printk("switch ok!cr3 is : %lu\n",cr3_address);
        	copy_err = copy_from_user(processtext, process_addr, process_size);
        	if(copy_err > 0)
        	{
        		printk("%lu\n",copy_err);
        		return;
        	}
        		
    		memset(process_hash_num, 0, SHA256_BLOCK_SIZE);
    		SHA256_Init(&sha256);
		SHA256_Update(&sha256,processtext,process_size);
		SHA256_Final(&sha256,process_hash_num);
    		for(k=0;k<SHA256_BLOCK_SIZE;k++)
	  	{
	     		process_text[k] = process_hash_num[k]; 
	  	}
	        a->base = process_text;
	        a->pid = proc->pid;
	        a->process_task = proc;
		list_add_tail_rcu(&a->list,&process_first.list);
		vfree(processtext);
		break;
	    }
	}
}

void delhash_process(int pid){
	struct process_benchmark *a;
	list_for_each_entry_rcu(a,&process_first.list,list)
	{
		if(a->pid == pid)
		{
			vfree(a->base);
			list_del_rcu(&a->list);
			vfree(a);
			break;
		}
	}
}
