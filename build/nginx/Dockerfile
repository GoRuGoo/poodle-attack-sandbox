FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    git \
    libpcre3 \
    python3 \
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

ENV PATH="/usr/local/ssl/bin:${PATH}"

ENV CFLAGS="-Wno-implicit-fallthrough"
RUN cd /root/ && \
    wget https://nginx.org/download/nginx-1.0.15.tar.gz && \
    tar -xzvf nginx-1.0.15.tar.gz && cd nginx-1.0.15 && \
    ./configure --with-http_ssl_module --with-openssl=../openssl-1.0.1i && \
    make  && make install

ENV PATH="/usr/local/nginx/sbin:${PATH}"

COPY ../conf/nginx.conf /usr/local/nginx/conf/nginx.conf

RUN chmod +x /usr/local/nginx/sbin/nginx

CMD ["sh","-c","python3 /root/target-nginx/python-test-server.py & /usr/local/nginx/sbin/nginx -g 'daemon off;'"]