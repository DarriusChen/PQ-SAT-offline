FROM python:3.12-slim

WORKDIR /app

# install dependency
COPY requirements.txt /app/

RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

CMD ["python", "crypto_inventory.py"]