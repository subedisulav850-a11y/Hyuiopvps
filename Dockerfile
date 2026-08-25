FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    RUNTIME_DIR=/data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt
COPY . .

EXPOSE 5000
VOLUME ["/data"]
CMD ["sh", "./run.sh"]