Frubee
==============================================================================

Frubee is a program for Internet connection.


Description
------------------------------------------------------------------------------
It's a program for GNU/Linux that connects the client to the router
and assign IP address dynamically (to the client on which it's executed),
without the use of the DHCP (no DHCP client, no DHCP server).<br />
The program (via pppd) also allows connection to the Internet with USB modem 
sticks or mobile phone plug to the PC with USB (not tested with smartphones).


Details about the dynamic assignment of the IP address
------------------------------------------------------------------------------
For now you can only run on client GNU/Linux with network wired card.
Frubee works even if in the LAN there are clients with other Operating 
Systems.

It manage correctly the dynamic assignment of the IP addresses if in a LAN
there are clients (detects only the IP address of the clients turned on)
 - connected with network wired card (both with DHCP and with Frubee)
 - connected via wireless (with DHCP) only if the network wireless card is
   active 

If the network wireless card is not active may occur an IP address conflict.
Frubee doesn't detect an IP address already used and so to the client is
assigned the same IP address of another client.


Installation
------------------------------------------------------------------------------
From shell, run the script "install.sh" (you must be root)

To build Frubee:
 - C++ compiler (install.sh use "g++")
 - library libpcap

Run from shell "sudo apt-get install libpcap0.8-dev" if you are building on 
Ubuntu or derivatives and it shows a message like this:<br />
frubee.cc:16:18: fatal error: pcap.h: No such file or directory
 #include <pcap.h>
compilation terminated.
Compilation error


Usage
------------------------------------------------------------------------------
Once installed, run from shell (you must be root):
sudo frubee "0" "0" 0 0 "0" 0
and follow the onscreen instructions.

Required programs
 - dialog: to select Nation, Router/Mobile
 - pppd: for the connection with USB modem sticks or mobile phone

To see the explanation of the parameters received, run from shell "frubee"

For deepening, read file README-from-ver-1.0.0


If the connection on the client is managed by DHCP: light test
------------------------------------------------------------------------------
You can try Frubee even if the client has already an IP address and it's
connected to the router via DHCP.

Example on Ubuntu 14.04 and Linux Mint 17
 0. Run Frubee
 1. If you're connected with "Router", to restore the original configuration
    restart PC.
    If you're connected with "Mobile", to restore the original configuration
    run
    sudo ln -f -s /run/resolvconf/resolv.conf /etc/resolv.conf
    and then restart PC.


If the connection on the client is managed by DHCP: full test
------------------------------------------------------------------------------
To avoid the risk of no longer be able to connect, before running the full 
test, it's advisable to check if Frubee connects to Internet with the mode
aforementioned, that is not by manually editing the original configuration.

For details read below.
 0. Disable DHCP server in the router
 1. To disable NetworkManager run "sudo mv /etc/init/network-manager.conf /etc/init/network-manager.conf-ORI"
 2. Restart PC
 3. Run Frubee
 4. Re-enable DHCP server in the router
 5. To re-enable NetworkManager run "sudo mv /etc/init/network-manager.conf-ORI /etc/init/network-manager.conf"
 6. If you're connected with "Router", to restore the original configuration
    restart PC.
    If you're connected with "Mobile", to restore the original configuration run
    sudo ln -f -s /run/resolvconf/resolv.conf /etc/resolv.conf
    and then restart PC.

Once restored the original configuration, PC could have another IP address.


Connect multiple 3G USB modem (multiple pppd)
------------------------------------------------------------------------------
To manage the multiple connection there are also the scripts:
 - frubee_dm (frubee detect modem). This script creates the list of device to pass to frubee for the connection of multiple 3G USB modem: detects only USB modem sticks, not detects mobile phone
 - frubee_tc (frubee test connection). This script shows connection status of ppp0, ppp1, ppp2, ppp3, ppp4

To explain the operating directions, I write an example. I tried with two modems, but Frubee can connect more.

**STEP 0**<br />
In order to have a correct detection of modems, restart your PC.

**STEP 1**<br />
Run in the shell
```
frubee_tc [URL on which run the ping test] [Interval of seconds between a control and the other]
```
it appears:
```
Bytes received in connection ppp0: NOT CONNECTED
Bytes received in connection ppp1: NOT CONNECTED
Bytes received in connection ppp2: NOT CONNECTED
Bytes received in connection ppp3: NOT CONNECTED
Bytes received in connection ppp4: NOT CONNECTED
        TO STOP THE SCRIPT PRESS CTRL+C
------------------------------------------------
```
If unplug and plug the modem, "frubee_dm" doesn't work correctly: in this case you have to restart the PC.


**STEP 2**<br />
Plug the first 3G USB modem (I have "Huawei E1820") and run frubee_dm in the shell 
It appears:
```
-------------------------------------------------
Parameter to be passed to frubee for the modem 1:
ttyUSB0
if not working, try:
ttyUSB1
if not working, try:
ttyUSB2
```

**STEP 3**<br />
Plug the second 3G USB modem (I have "Huawei E220") and run frubee_dm in the shell  
It appears:
```
-------------------------------------------------
Parameter to be passed to frubee for the modem 1:
ttyUSB0
if not working, try:
ttyUSB1
if not working, try:
ttyUSB2
-------------------------------------------------
Parameter to be passed to frubee for the modem 2:
ttyUSB3
if not working, try:
ttyUSB4
```

**STEP 4**<br />
To connect the modem 1, run
```
frubee "0" "0" 0 0 "ttyUSB0" 0
```

situation in frubee_tc once connected the modem 1
```
Bytes received in connection ppp0: 102
Bytes received in connection ppp1: NOT CONNECTED
Bytes received in connection ppp2: NOT CONNECTED
Bytes received in connection ppp3: NOT CONNECTED
Bytes received in connection ppp4: NOT CONNECTED
        TO STOP THE SCRIPT PRESS CTRL+C
------------------------------------------------
Bytes received in connection ppp0: 432
Bytes received in connection ppp1: NOT CONNECTED
Bytes received in connection ppp2: NOT CONNECTED
Bytes received in connection ppp3: NOT CONNECTED
Bytes received in connection ppp4: NOT CONNECTED
        TO STOP THE SCRIPT PRESS CTRL+C
------------------------------------------------
```

**STEP 5**<br />
Once connected the modem 1, to connect the modem 2, run
```
frubee "0" "0" 0 0 "ttyUSB3" 0	
```

situation in frubee_tc once connected the modem 1 and modem 2
```
Bytes received in connection ppp0: 4810
Bytes received in connection ppp1: 158
Bytes received in connection ppp2: NOT CONNECTED
Bytes received in connection ppp3: NOT CONNECTED
Bytes received in connection ppp4: NOT CONNECTED
        TO STOP THE SCRIPT PRESS CTRL+C
------------------------------------------------
Bytes received in connection ppp0: 4810
Bytes received in connection ppp1: 242
Bytes received in connection ppp2: NOT CONNECTED
Bytes received in connection ppp3: NOT CONNECTED
Bytes received in connection ppp4: NOT CONNECTED
        TO STOP THE SCRIPT PRESS CTRL+C
------------------------------------------------
```


Try Frubee on Precise Puppy 5.7.1
------------------------------------------------------------------------------
If you want to try Frubee on Precise Puppy 5.7.1 read the following URL:
http://murga-linux.com/puppy/viewtopic.php?t=99766


License
------------------------------------------------------------------------------
See COPYING for license information.
