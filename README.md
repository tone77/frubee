Frubee
==============================================================================

Frubee is a program for Internet connection.


Description
------------------------------------------------------------------------------
It's a program for GNU/Linux that connects the client to the router
and assign IP address dynamically (to the client on which it's executed),
without the use of the DHCP (no DHCP client, no DHCP server).
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
From shell, run the script "install.sh"

To build Frubee:
 - C++ compiler (install.sh use "g++")
 - library libpcap

Run from shell "sudo apt-get install libpcap0.8-dev" if you are building on 
Ubuntu or derivatives and it shows a message like this:
frubee.cc:16:18: fatal error: pcap.h: No such file or directory
 #include <pcap.h>
compilation terminated.
Compilation error


Usage
------------------------------------------------------------------------------
Once installed, run from shell (you must be root):
sudo frubee "0" "0" 0
and follow the onscreen instructions.

Required programs
 - dialog: to select Nation, Router/Mobile
 - pppd: for the connection with USB modem sticks or mobile phone

To see the explanation of the parameters received, run from shell "frubee"

For deepening, read file README


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


Try Frubee on Precise Puppy 5.7.1
------------------------------------------------------------------------------
If you want to try Frubee on Precise Puppy 5.7.1 read the following URL:
http://murga-linux.com/puppy/viewtopic.php?t=99766


License
------------------------------------------------------------------------------
See COPYING for license information.
