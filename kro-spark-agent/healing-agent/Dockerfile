FROM python:3.11-slim
COPY zscaler-root.crt /usr/local/share/ca-certificates/zscaler-root.crt
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --cert /etc/ssl/certs/ca-certificates.crt  -r requirements.txt

COPY spark_healing_agent.py .

CMD ["python", "spark_healing_agent.py"]
