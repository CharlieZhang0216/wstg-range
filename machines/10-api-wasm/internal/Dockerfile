FROM python:3.12-slim
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy
WORKDIR /app
COPY app.py .
EXPOSE 8080
CMD ["python", "app.py"]