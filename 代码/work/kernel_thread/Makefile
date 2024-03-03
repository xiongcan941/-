obj-m += tt.o
KBUILD_EXTRA_SYMBOLS += /home/xc/work/hook-master/Module.symvers 
KBUILD_EXTRA_SYMBOLS += /home/xc/work/Benchmark_database_establishment/Module.symvers

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
        
