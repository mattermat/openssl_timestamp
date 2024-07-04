# openssl_timestamp
Example code to get hardware timestamp with openssl

### why
I'm working on a HFT system written purely in C.
Every HFT system needs to be measurable. In particular, it has to be measurable in terms of latency.

Latency has a lot of meaning in the HFT space.
One of them is the tick to trade (ttt).
The ttt has three parts:
- the path from the exchange to the hardware components of our machine
- the path inside our machine to elaborate an operation (e.g. a trade) based on the received update
- the path from the hardware components of our machine to the exchange

The first and the third ones depend on external factors (like distance from the exchange servers) and can be reduced via colocation.
The second one depends on our hardware and our software and can be reduced either optimizing the power of our machine or improving the code (in general is easier to achieve better performance by optimizing code).
However, before starting any optimization, we need to measure in order to be able to benchmark different algorithms and details.
Given also that tipycally, for solo developers, this is more of a journey than a one-off solution, we are at beginning of our optimization path and any path that use https to move (this is the case of websocket connections to crypto exchanges), the best choice is to not re-implement TLS from scratch but instead use the OpenSSL library.

Well, integrating the linux hardware timestamp in OpenSSL has not been an easy work, given the opacque documentation around BIO.
Anyway, the conecpt is to have a BIO for managing the socket operations and basically use recvmsg to get ancillary data on the connection containing also timestamps.

I experienced some obstacles in using custom BIO methods with OpenSSL 3.0. Scraping the entire web, I found in a little comment of a stackoverflow answer that it should be buggy in that OpenSSL version and it should work on more recent versions. Using OpenSSL 3.3.1 seems to make my BIO method work so in the code you will also find how to install OpenSSL 3.3.1 and how to build with the folder (in order to keep intact the system OpenSSL version).

### how it works
#### 1. install latest version of openssl
`sudo apt install build-essential wget`

`wget https://www.openssl.org/source/openssl-3.3.1.tar.gz`

`tar xvzf openssl-3.3.1.tar.gz`

`cd openssl-3.3.1`

`./config '-Wl,-rpath,$(LIBRPATH)' -Wl,--enable-new-dtags --prefix=/usr/local --openssldir=/usr/local/openssl`

`make`

`sudo make install`

This would install the openssl binary in /usr/local/bin (`$ /usr/local/bin/openssl version` to test the version).

Then clean up:
`cd .. && rm -rf openssl-3.3.1`

#### 2. build and run the example
`make`

`sudo ./main`