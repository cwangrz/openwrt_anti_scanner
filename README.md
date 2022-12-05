# openwrt_anti_scanner
Simple python script to filter out port 22/80 scanner ips and ban them through iptables.

This is largely for personal use.

Instruction
--- 
1. make sure python3 is installed on your openwrt firmware
2. upload script to /root
3. create cron job (for example on every 30th minute）
```
*/30 * * * * python3 /root/anti_scanner.py
```

Behavior
---
1. The script filters output from `logread`
2. The script creates a log file (abusers.log by default)
3. The script creates a .txt file including all previously detected abuser ips (banlist.txt by default)
4. The banlist is used for persistant purposes
5. You may add or modify the filter tokens as needed

Caution
---
1. For now, ips are banned forever unless manually removed
