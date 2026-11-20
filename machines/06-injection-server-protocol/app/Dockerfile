FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN printf '%s\n' 'WSTG-M06{pickle_rce_server_side_injection}' > /flag.txt

EXPOSE 5000
CMD ["python", "app.py"]