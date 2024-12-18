# Dockerfile for Python
FROM python:3.12-slim

WORKDIR /app

# install dependency
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . /app