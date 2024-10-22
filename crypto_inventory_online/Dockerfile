FROM python:3.12-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

# Set the volume
VOLUME ["app/crypto_inventory_report"]

CMD ["python", "crypto_inventory_online.py"]
