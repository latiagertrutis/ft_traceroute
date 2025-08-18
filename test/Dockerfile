FROM debian:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    traceroute \
    netbase \
    python3 \
    pipx \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

RUN PIPX_BIN_DIR=/usr/local/bin pipx install robotframework

COPY test/resources/ /resources/
COPY test/test/ /test/

ENTRYPOINT ["sleep", "infinity"]
# ENTRYPOINT [ "robot", "--outputdir", "output", "test" ]
