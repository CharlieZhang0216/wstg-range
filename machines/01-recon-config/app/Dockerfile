FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# WSTG-CONF-09: world-writable upload dir, world-readable secret config.
RUN mkdir -p /srv/data/uploads \
 && printf '[database]\nhost=db\nuser=portal\npassword=Sup3rS3cretPortalPW\n' > /srv/data/config.ini \
 && chmod 0777 /srv/data/uploads \
 && chmod 0644 /srv/data/config.ini

EXPOSE 5000
CMD ["python", "app.py"]