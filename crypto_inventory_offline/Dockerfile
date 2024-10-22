# Dockerfile for Python
FROM python:3.12-slim

WORKDIR /app

# 安裝依賴
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app