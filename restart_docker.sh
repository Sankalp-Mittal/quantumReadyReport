docker stop pqc-scanner
docker rm pqc-scanner
docker build -t pqc-scanner .
docker run -d \
  --name pqc-scanner \
  --restart unless-stopped \
  -p 5000:5000 \
  -e PORT=5000 \
  -e REPORT_TTL=3600 \
  pqc-scanner