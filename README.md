# forwarp

Linux only. This is a PoC.

    $ make
    $ sudo setcap cap_net_admin,cap_net_raw=ep ./forwarp
    $ ./forwarp eth0 eth1

This will forward ARP requests from `eth0` to `eth1` and update
the ARP table of `eth0` by capturing all the ARP responses received by `eth1`.

    ,---------------------------------------,
    | ,-----------------------------------, |
    | |              forwarp              | |
    | |             ,-----------,         | |
    '-|-------------|-----------|---------|-'
      |             |           |         |
    ,-'------,      v           |  ,------|-,
    |        |,-------------,   |  |      '-|--ARP-REQ->
    |  eth0  ==  ARP cache  |   |  |  eth1  |
    |        |'-------------'   '--|--------|--ARP-REP--
    '--------'                     '--------'

### Notes

- I wasn't able to capture local ARP requests with `ETH_P_ARP`.
I had to use `ETH_P_ALL` with BPF to do it without imacting perf too much.

- I wasn't able to use the same socket for `eth0` and `eth1`.
It's sad but it makes sense...
