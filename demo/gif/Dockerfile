# Pre-baked image for recording the demo GIF: all prerequisites installed and
# the enforcer binary built, so a recorded run shows only the demo output —
# not apt/go build noise. Build from the repo root:
#   docker build -f demo/gif/Dockerfile -t warden-demo .
FROM ubuntu:24.04

RUN apt-get update -q && apt-get install -y --no-install-recommends \
        nftables iproute2 iputils-ping curl ca-certificates \
        python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

ARG GO_VERSION=1.26.4
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-$(dpkg --print-architecture).tar.gz" \
        | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:$PATH

WORKDIR /warden
COPY requirements-test.txt .
RUN pip install --break-system-packages -r requirements-test.txt

COPY . .
RUN cd enforcer && go build -o bin/warden-enforcer ./cmd/warden-enforcer

CMD ["python3", "demo/run_demo.py"]
