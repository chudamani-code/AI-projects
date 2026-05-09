FROM python:3.12-slim
WORKDIR /app
RUN mkdir /data
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY *.py .
RUN useradd -r -u 1001 vending && chown -R vending /app /data
USER vending
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8100"]
