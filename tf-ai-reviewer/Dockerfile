FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY reviewer/ ./reviewer/
COPY cli.py .
RUN useradd -r -u 1001 reviewer && chown -R reviewer /app
USER reviewer
CMD ["uvicorn", "reviewer.main:app", "--host", "0.0.0.0", "--port", "8200"]
