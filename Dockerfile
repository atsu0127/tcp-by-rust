FROM rust:1.75-buster

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get -y install sudo iptables ethtool curl less git bridge-utils openssh-server ncat traceroute tshark && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir /var/run/sshd

WORKDIR /workspace

# SSH接続用ユーザーの作成
RUN useradd -m atsu0127 && yes pass | passwd atsu0127
RUN echo 'atsu0127 ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# SSH接続用のポートを開放
EXPOSE 22