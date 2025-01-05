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
    net-tools \
    iptables \
    dsniff \
    sudo \
    jq \
    dsniff \
    python3-pip \
    libnetfilter-queue-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install scapy NetfilterQueue

RUN curl -sSL https://install.python-poetry.org | python3

RUN git clone https://github.com/tintinweb/scapy-ssl_tls.git && cd scapy-ssl_tls && python3 setup.py install

ENV PATH="/root/.local/bin:$PATH"