cmd_/home/xc/kernel_thread/modules.order := {   echo /home/xc/kernel_thread/ttt.ko; :; } | awk '!x[$$0]++' - > /home/xc/kernel_thread/modules.order
