FROM python:3.12-slim
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py graphql_schema.py ./
EXPOSE 5000
CMD ["python", "app.py"]