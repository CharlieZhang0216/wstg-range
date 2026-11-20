FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

# ATHZ-01: public docroot plus a real flag file OUTSIDE the intended root.
RUN mkdir -p /srv/files /srv/secret \
 && printf 'Public brochure. Nothing sensitive here.\n' > /srv/files/public.txt \
 && printf 'WSTG-M03{traversal_outside_the_docroot}\n' > /srv/secret/flag.txt \
 && chmod 0644 /srv/secret/flag.txt

EXPOSE 5000
CMD ["python", "app.py"]