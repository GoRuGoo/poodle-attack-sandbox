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
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install scapy NetfilterQueue