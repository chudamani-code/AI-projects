FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .

# Non-root user for least-privilege execution
RUN useradd -r -u 1001 agentuser \
 && chown -R agentuser:agentuser /app

USER agentuser

CMD ["python", "main.py"]
