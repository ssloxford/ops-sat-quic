# ops-sat-quic
## Installation
Ensure that the following tools are installed:
- pkg-config
- autoconf
- automake
- autotools-dev
- libtool
### Install wolfSSL
```
git clone -b v5.7.0-stable git@github.com:wolfssl/wolfssl.git
cd wolfssl
autoreconf -i
./configure --enable-all --enable-harden --disable-ech
make
sudo make install
```
### Install NGTCP2
```
git clone git@github.com:ngtcp2:ngtcp2.git
cd ngtcp2
autoreconf -i
./configure PKG_CONFIG_PATH=usr/local/lib/pkgconfig --with-wolfssl
make
sudo make install
ldconfig
```
## Compiling sourcecode
Inside `/home/exp267/`:
`gcc -o client.o client.c utils.c connection.c -lwolfssl -lngtcp2 -lngtcp2_crypto_wolfssl`
`gcc -o server.o server.c utils.c connection.c -lwolfssl -lngtcp2 -lngtcp2_crypto_wolfssl`
