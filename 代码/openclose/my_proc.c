#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h> 
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/module.h>
#define BUFSIZE  7

#define make(_name) \
{                  \
	.name = (_name), \
}

extern int open(int i);
extern void close(int i);
static struct proc_dir_entry *input, *output,*amodule;
static char *buf;
static char *mybuf;
static char name1[56];
static char name2[56];

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

static ssize_t addmodule(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
  if(count <= 0)
    return -EFAULT;
  if(copy_from_user(name1, ubuf, sizeof(name1)))
    return -EFAULT;
  printk("add :%s\n",name1);
  return sizeof(name1);
}


static struct proc_ops fo_input = 
{
  .proc_write = mywrite,
};

static struct proc_ops fo_output = 
{
  .proc_read = myread,
};

static struct proc_ops addmodule_input = 
{
  .proc_write = addmodule,
};
static int proc_init(void)
{
  buf = (char*)kmalloc(BUFSIZE+1, GFP_KERNEL);
  mybuf = (char*)kmalloc(BUFSIZE+1, GFP_KERNEL);
  if(buf == NULL)
  {
    printk("kmalloc failure\n");
    return -EFAULT;
  }
  memset(buf, 0, BUFSIZE+1);
  memset(name1, 0, sizeof(name1));
  memset(name2, 0, sizeof(name2));
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
  amodule=proc_create("amodule",0666,NULL,&addmodule_input);
  if(amodule == NULL)
    return -ENOMEM;
  return 0;
}
static void proc_cleanup(void)
{
  proc_remove(input);
  proc_remove(output);
  proc_remove(amodule);
  kfree(buf);
  kfree(mybuf);
  printk("hook switch cleanup\n");
}
module_init(proc_init);
module_exit(proc_cleanup);
MODULE_LICENSE("GPL");
