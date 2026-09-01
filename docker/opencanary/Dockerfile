FROM python:3.11-slim

# Dependencias de compilación para las dependencias de OpenCanary
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential libffi-dev libssl-dev python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir opencanary scapy

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 21

ENTRYPOINT ["/entrypoint.sh"]
