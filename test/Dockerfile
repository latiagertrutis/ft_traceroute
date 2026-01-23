FROM debian:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    wget \
    netbase \
    python3 \
    pipx \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

RUN wget http://downloads.sourceforge.net/traceroute/traceroute-2.1.6.tar.gz -O /tmp/traceroute-2.1.6.tar.gz \
    && tar -zxvf /tmp/traceroute-2.1.6.tar.gz -C /tmp \
    && cd /tmp/traceroute-2.1.6 \
    && make \
    && cp /tmp/traceroute-2.1.6/traceroute/traceroute /traceroute

RUN PIPX_BIN_DIR=/usr/local/bin pipx install robotframework

COPY test/test/ /test/
COPY Makefile /ft_traceroute_dir/
COPY src/ /ft_traceroute_dir/src/

RUN cd /ft_traceroute_dir && make BEAR=

# ENTRYPOINT ["sleep", "infinity"]
ENTRYPOINT [ "robot", "--outputdir", "output", "test" ]
