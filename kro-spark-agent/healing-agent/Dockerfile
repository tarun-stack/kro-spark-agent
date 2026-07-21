FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY spark_healing_agent.py .

CMD ["python", "spark_healing_agent.py"]
