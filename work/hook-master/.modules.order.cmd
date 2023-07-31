cmd_/home/xc/work/hook-master/modules.order := {   echo /home/xc/work/hook-master/hooking.ko; :; } | awk '!x[$$0]++' - > /home/xc/work/hook-master/modules.order
