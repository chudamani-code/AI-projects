FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py .
RUN useradd -r -u 1001 apiuser && chown -R apiuser /app
USER apiuser
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
