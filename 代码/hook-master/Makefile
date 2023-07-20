obj-m += hooking.o
KBUILD_EXTRA_SYMBOLS=/home/xc/kernel_thread/Module.symvers
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
        
