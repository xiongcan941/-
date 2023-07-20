cmd_/home/xc/hook-master/modules.order := {   echo /home/xc/hook-master/hooking.ko; :; } | awk '!x[$$0]++' - > /home/xc/hook-master/modules.order
