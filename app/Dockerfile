FROM python:3.12-slim

Run useradd -m -u 1000 appuser

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY . .
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 5000
CMD ["uvicorn", "app;app", "--host", "0.0.0.0", "--port",  "5000"]
