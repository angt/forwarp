# forwarp

Linux only. This is a PoC.

    $ make
    $ sudo setcap cap_net_admin,cap_net_raw=ep ./forwarp
    $ ./forwarp eth0 eth1
