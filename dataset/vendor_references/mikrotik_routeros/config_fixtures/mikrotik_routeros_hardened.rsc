# MikroTik RouterOS Hardened Script
/system identity set name="MikroTik-Core-CCR2004"
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set ssh port=22 address=192.168.88.0/24
set api disabled=yes
set winbox address=192.168.88.0/24
/snmp
set enabled=yes
/snmp community
set [ find default=yes ] name=<SANITIZED_SNMP_COMMUNITY>
/system ntp client
set enabled=yes
/system ntp client servers
add address=192.168.88.1
/ip firewall filter
add action=accept chain=input connection-state=established,related comment="Accept established/related"
add action=drop chain=input connection-state=invalid comment="Drop invalid packets"
add action=accept chain=input protocol=icmp comment="Allow ICMP"
add action=accept chain=input in-interface=ether1 src-address=192.168.88.0/24 comment="Allow management subnet"
add action=drop chain=input comment="Drop all other input traffic"
