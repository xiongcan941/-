obj-m += my_proc.o
KBUILD_EXTRA_SYMBOLS += /home/xc/hook-master/Module.symvers 

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
        
