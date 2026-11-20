FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY openssl.cnf /app/openssl.cnf
COPY gen_cert.py server.py ./

# WSTG-CRYP-01: expired, self-signed, hostname-mismatched RSA-1024/SHA1 cert.
RUN python gen_cert.py

# Activate the legacy provider and drop the system TLS floor to TLSv1.
ENV OPENSSL_CONF=/app/openssl.cnf

EXPOSE 8443
CMD ["python", "server.py"]