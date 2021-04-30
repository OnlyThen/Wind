# Wind

A C implementation of Socks5 proxy

# Build

```
mkdir build
cd build
cmake ../src
make
```

# Products

1. local:  proxy client
2. remote: proxy server

# Usage

1. local:  [-l remote_ip] [-p remote_port] [-s listen_port] [-m xor|rc4] [-e key]
2. remote: [-p server_port] [-m xor|rc4] [-e key]