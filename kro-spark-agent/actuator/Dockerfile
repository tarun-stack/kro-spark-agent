FROM python:3.11-slim
COPY zscaler-root.crt /usr/local/share/ca-certificates/zscaler-root.crt
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --cert /etc/ssl/certs/ca-certificates.crt -r requirements.txt

COPY server.py .

RUN useradd -u 1000 -m actuator
USER 1000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080"]
