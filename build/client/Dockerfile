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
    vim \
    && rm -rf /var/lib/apt/lists/*

RUN cd /root/ && \
    wget https://www.openssl.org/source/openssl-1.0.1i.tar.gz && \
    tar -xzvf openssl-1.0.1i.tar.gz && \
    cd openssl-1.0.1i && \
    ./config shared zlib --prefix=/usr/local/ssl && \
    make && make install


ENV LD_LIBRARY_PATH=/usr/local/ssl/lib:$LD_LIBRARY_PATH
RUN cd /root/ && \
    wget https://curl.se/download/curl-7.32.0.tar.gz && \
    tar -xzvf curl-7.32.0.tar.gz && \
    cd curl-7.32.0 && \
    ./configure --with-ssl=/usr/local/ssl --prefix=/usr/local/curl-test && \
    make && make install
ENV PATH="/usr/local/curl-test/bin:${PATH}"


RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash && \
    export NVM_DIR="$HOME/.nvm" && \
    [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh" && \
    nvm install 0