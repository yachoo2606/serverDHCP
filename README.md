# serverDHCP

DHCP server written in c++ enabling automatic configuration of devices in the local network 
from the pool of addresses provided as an argument of program and configuration of 
the dns server and default gateway on the device.

## configure
to compile program type in console: 
```
make
```

## run
to run program type in console: 
```
./program <interface> <startingIP> <endingIP> <mask> <default gateway> <leese time> <DNSaddr>
```
