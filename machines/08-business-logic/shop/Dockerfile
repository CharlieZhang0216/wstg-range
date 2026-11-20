FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

RUN mkdir -p /srv/uploads

EXPOSE 5000
# Single worker, many threads: concurrent requests share the process and hit
# the check-then-act race windows in the coupon/checkout logic.
CMD ["gunicorn", "-w", "1", "--threads", "16", "-b", "0.0.0.0:5000", "--timeout", "120", "app:app"]