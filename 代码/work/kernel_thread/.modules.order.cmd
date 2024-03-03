cmd_/home/xc/work/kernel_thread/modules.order := {   echo /home/xc/work/kernel_thread/tt.ko; :; } | awk '!x[$$0]++' - > /home/xc/work/kernel_thread/modules.order
