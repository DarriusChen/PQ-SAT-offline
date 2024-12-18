# Dockerfile for Python
FROM python:3.12-slim

WORKDIR /app

# install dependency
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
RUN mkdir -p /app/logs && chmod -R 777 /app/logs
RUN mkdir -p /app/crypto_inventory_report && chmod -R 777 /app/crypto_inventory_report

# Copy application files
COPY . /app