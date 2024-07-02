# openssl_timestamp
Example code to get hardware timestamp with openssl

### install latest version of openssl
`sudo apt install build-essential wget`
`wget https://www.openssl.org/source/openssl-3.3.1.tar.gz`
`tar xvzf openssl-3.3.1.tar.gz`

`cd openssl-3.3.1`
`./config '-Wl,-rpath,$(LIBRPATH)' -Wl,--enable-new-dtags --prefix=/usr/local --openssldir=/usr/local/openssl`

`make`
`sudo make install`

This would install the openssl binary in /usr/local/bin (`$ /usr/local/bin/openssl version` to test the version).
