FROM python:3.11-slim

# System dependencies — openssl + coreutils (timeout) are required by scan.sh
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl coreutils curl unzip bash \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download subfinder binary
RUN curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v2.13.0/subfinder_2.13.0_linux_amd64.zip \
      -o /tmp/sf.zip \
 && unzip -o /tmp/sf.zip subfinder -d bin/ \
 && chmod +x bin/subfinder \
 && rm /tmp/sf.zip

# Copy source
COPY . .
RUN chmod +x scan.sh && mkdir -p output

EXPOSE 5000

# Use gunicorn in production; threaded mode keeps SSE streams alive
CMD gunicorn \
      --bind 0.0.0.0:${PORT:-5000} \
      --workers 2 \
      --threads 8 \
      --timeout 660 \
      --worker-class gthread \
      app:app
