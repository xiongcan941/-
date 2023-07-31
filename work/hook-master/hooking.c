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
#include <linux/proc_fs.h>
#include <linux/slab.h>

MODULE_AUTHOR("xc");
MODULE_DESCRIPTION("hooking");
MODULE_VERSION("0.02");
MODULE_LICENSE("GPL");

#define BUFSIZE  7

#define make(_name) \
{                  \
	.name = (_name), \
}

static struct proc_dir_entry *input, *output;
static char *buf;
static char *mybuf;

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


/*--------------------------notifier------------------------------------------*/
static RAW_NOTIFIER_HEAD(test_chain);

/*
 自定义的注册函数，将notifier_block节点加到刚刚定义的test_chain这个链表中来
*/
int register_test_notifier(struct notifier_block *nb)
{
	return raw_notifier_chain_register(&test_chain, nb);
}
EXPORT_SYMBOL(register_test_notifier);

int unregister_test_notifier(struct notifier_block *nb)
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
   err = test_notifier_call_chain(2, mod);
   return orig_fork(args);
}

static asmlinkage long (*orig_exit)(long code);

asmlinkage int hook_exit(long code)
{
    int err;
    printk(KERN_INFO "exited %s,pid: %d\n",current->comm,current->pid);
    err = test_notifier_call_chain(2, mod);
    return orig_exit(code);
}

static asmlinkage long (*orig_load)(struct module *mod);

asmlinkage int hook_load(struct module *mod)
{
   int err;
   pr_info("module name: %s\n", mod->name);
   err = test_notifier_call_chain(1, mod);
   return orig_load(mod);
}

static asmlinkage long (*orig_free_module)(struct module *mod);

asmlinkage int hook_free_module(struct module *mod)
{
   int err;
   err = test_notifier_call_chain(1, mod);
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
      err = test_notifier_call_chain(2, mod);
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
    err = test_notifier_call_chain(2, mod);
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

/* Module initialization function */
static int __init hooking_init(void)
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
    return 0;
}

static void __exit hooking_exit(void)
{
    /* Unhook and restore the syscall and print to the kernel buffer */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    proc_remove(input);
    proc_remove(output);
    kfree(buf);
    kfree(mybuf);
    printk(KERN_INFO "hooking: Unloaded :-(\n");
}
 
module_init(hooking_init);
module_exit(hooking_exit);


