# Gunakan image Python yang ringan
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install dependensi sistem untuk stabilitas library Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements dan install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn

# Copy seluruh kode aplikasi
COPY . .

# Pastikan folder instance ada untuk database SQLite
RUN mkdir -p instance

# Jalankan dengan Gunicorn (Port akan diatur otomatis oleh Cloud melalui variable $PORT)
CMD gunicorn --bind 0.0.0.0:$PORT app:app