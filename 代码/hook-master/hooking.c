#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/fs_struct.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/path.h>
#include "ftrace_helper.h"
#include <linux/mutex.h>
#include <asm/uaccess.h>
#include <linux/notifier.h>
#include <linux/types.h>

MODULE_AUTHOR("xc");
MODULE_DESCRIPTION("hooking");
MODULE_VERSION("0.02");

bool flag = false;

/*--------------------------notifier------------------------------------------*/
static RAW_NOTIFIER_HEAD(test_chain);

/*
 自定义的注册函数，将notifier_block节点加到刚刚定义的test_chain这个链表中来
*/
static int register_test_notifier(struct notifier_block *nb)
{
return raw_notifier_chain_register(&test_chain, nb);
}
EXPORT_SYMBOL(register_test_notifier);

static int unregister_test_notifier(struct notifier_block *nb)
{
return raw_notifier_chain_unregister(&test_chain, nb);
}
EXPORT_SYMBOL(unregister_test_notifier);

/*
* 自定义的通知链表的函数，即通知test_chain指向的链表中的所有节点执行相应的函数
*/
static int test_notifier_call_chain(unsigned long val, void *v)
{
return raw_notifier_call_chain(&test_chain, val, v);
}
/*--------------------------notifier------------------------------------------*/


/*--------------------------hook------------------------------------------*/
static asmlinkage long (*orig_fork)(struct kernel_clone_args *args);

asmlinkage int hook_fork(struct kernel_clone_args *args)
{  
   int err;
   struct mm_struct *mm=current->mm;
   printk(KERN_INFO "fork %s,pid: %d \n",current->comm,current->pid);
   
   return orig_fork(args);
}

static asmlinkage long (*orig_exit)(long code);

asmlinkage int hook_exit(long code)
{
    int err;
    printk(KERN_INFO "exited %s,pid: %d\n",current->comm,current->pid);
    
    return orig_exit(code);
}

static asmlinkage long (*orig_load)(struct module *mod);

asmlinkage int hook_load(struct module *mod)
{
   int err;
   pr_info("module name: %s\n", mod->name);
   
   if(flag)
   {
     err = test_notifier_call_chain(11, mod);
     flag = false;
   }else{
     flag = false;
     err = test_notifier_call_chain(1, mod);
   }
   return orig_load(mod);
}

static asmlinkage long (*orig_free_module)(struct module *mod);

asmlinkage int hook_free_module(struct module *mod)
{
   int err;
   if(flag)
   {
     err = test_notifier_call_chain(12, mod);
     flag = false;
   }else{
     flag = false;
     err = test_notifier_call_chain(1, mod);
   }
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
      printk(KERN_INFO "RELOAD: %s\n",current->comm);
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
    
    printk(KERN_INFO "execve: %s\n",filename->name);
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

int open(int i)
{
	int err;
	err = fh_install_hook(&hooks[i]);
    	if(err)
        return err;
        return 0;
}
void close(int i)
{
	fh_remove_hook(&hooks[i]);
}
EXPORT_SYMBOL(open);
EXPORT_SYMBOL(close);
/*--------------------------up and down------------------------------------------*/

static asmlinkage long (*orig_kill)(const struct pt_regs *pt_regs);

asmlinkage int hook_kill(const struct pt_regs *pt_regs)
{  
   pid_t pid = (pid_t) pt_regs->di;
   int sig = (int) pt_regs->si;
   int err;
   switch (sig) {
		case SIG1:		
    			err = fh_install_hook(&hooks[0]);
    			if(err)
        			return err;
			break;
		
		case SIG2:
    			err = fh_install_hook(&hooks[1]);
    			if(err)
        			return err;
			break;

		case SIG3:
			err = fh_install_hook(&hooks[2]);
    			if(err)
        			return err;
			break;
		case SIG4:
			err = fh_install_hook(&hooks[3]);
    			if(err)
        			return err;
			break;
		case SIG5:
			err = fh_install_hook(&hooks[4]);
    			if(err)
        			return err;
			break;
		case SIG6:		
    			fh_remove_hook(&hooks[0]);
    			
			break;
		
		case SIG7:
    			fh_remove_hook(&hooks[1]);
    			
			break;
		
		case SIG8:
			fh_remove_hook(&hooks[2]);
    			
			break;
		case SIG9:
			fh_remove_hook(&hooks[3]);
    			
			break;
		case SIG10:
			fh_remove_hook(&hooks[4]);
    			
			break;
		case SIG11:
			flag = true;
    			
			break;
		default:
   			return orig_kill(pt_regs);
   		}
   	return 0;
}
static struct ftrace_hook hook1 = HOOK("__x64_sys_kill", hook_kill, &orig_kill);

/*--------------------------up and down------------------------------------------*/

/* Module initialization function */
static int __init hooking_init(void)
{
    /* Hook the syscall and print to the kernel buffer */
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;
    err = fh_install_hook(&hook1);
    if(err)
        return err;
    printk(KERN_INFO "hooking: Loaded >:-)\n");
    return 0;
}

static void __exit hooking_exit(void)
{
    /* Unhook and restore the syscall and print to the kernel buffer */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    fh_remove_hook(&hook1);
    printk(KERN_INFO "hooking: Unloaded :-(\n");
}
 
module_init(hooking_init);
module_exit(hooking_exit);
MODULE_LICENSE("GPL");

