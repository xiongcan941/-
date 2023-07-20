cmd_/home/xc/openclose/modules.order := {   echo /home/xc/openclose/my_proc.ko; :; } | awk '!x[$$0]++' - > /home/xc/openclose/modules.order
