FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    git \
    libpcre3 \
    libpcre3-dev \
    zlib1g \
    zlib1g-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN cd /root/ && \
    wget https://www.openssl.org/source/openssl-1.0.1i.tar.gz && \
    tar -xzvf openssl-1.0.1i.tar.gz && \
    cd openssl-1.0.1i && \
    ./config shared zlib --prefix=/usr/local/ssl && \
    make && make install
