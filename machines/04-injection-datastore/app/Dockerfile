# Stage 1: vendor alasql (client-side SQL engine for WSTG-INJT-05 / 05.8)
# so the browser loads it same-origin - no third-party CDN calls at runtime.
FROM node:20-alpine AS js
WORKDIR /js
RUN npm install --no-cache-dir alasql@4.6.6

FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY data/ data/
COPY static/ static/
COPY --from=js /js/node_modules/alasql/dist/alasql.min.js static/alasql.min.js
EXPOSE 5000
CMD ["python", "app.py"]