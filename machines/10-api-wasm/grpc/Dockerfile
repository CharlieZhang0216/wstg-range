FROM python:3.12-slim
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY lab.proto server.py ./
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. lab.proto
EXPOSE 50051
CMD ["python", "server.py"]