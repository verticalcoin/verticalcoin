Features and Specs
==================================

Specs
----------------------
- LWMA difficulty algorithm https://github.com/zawy12/difficulty-algorithms/issues/3
- Lbk3 POW algorithm - we fork on Block 100 000
- vNodes 
- Tor integration
- Blocktime: 2 minutes 
- Blocksize: 2 MB 
- Coin Maturity: 50
- Maximum Supply: 35 million 

Linux Build Instructions and Notes
==================================

Dependencies
----------------------
1.  Update packages

        sudo apt-get update

2.  Install required packagages

        sudo apt-get install build-essential libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils libboost-all-dev

3.  Install Berkeley DB 4.8

        sudo apt-get install software-properties-common
        sudo add-apt-repository ppa:bitcoin/bitcoin
        sudo apt-get update
        sudo apt-get install libdb4.8-dev libdb4.8++-dev

4.  Install QT 5

        sudo apt-get install libminiupnpc-dev libzmq3-dev
        sudo apt-get install libqt5gui5 libqt5core5a libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev protobuf-compiler libqrencode-dev

Build
----------------------
1.  Clone the source:

        git clone https://github.com/verticalcoin/verticalcoin

2.  Build Verticalcoin-core:

    Configure and build the headless verticalcoin binaries as well as the GUI (if Qt is found).

    You can disable the GUI build by passing `--without-gui` to configure.
        
        ./autogen.sh
        ./configure
        make

3.  It is recommended to build and run the unit tests:

        make check

        
vNode Setup
=====================================
See (VNODE.md) for instructions.

        
Mining 
=====================================
We have a build in CPU miner. "setgenerate true 1" will activate it for 1 CPU. GPU mining on Windows is possible with ccminer https://github.com/tpruvot/ccminer/releases


Mac OS X Build Instructions and Notes
=====================================
See (doc/build-osx.md) for instructions on building on Mac OS X.


Windows (64/32 bit) Build Instructions and Notes
=====================================
See (doc/build-windows.md) for instructions on building on Windows 64/32 bit.


Docker Image to build Verticalcoin (Linux/Windows)
=====================================
https://github.com/verticalcoin/verticalcoin-docker/
