FROM python:3.12-slim

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    DEBIAN_FRONTEND=noninteractive

# Chromium runtime libraries (Debian bookworm names; playwright --with-deps
# expects Ubuntu-only font packages, so install the real deps manually).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libdbus-1-3 \
    libxkbcommon0 libatspi2.0-0 libx11-6 libxcomposite1 libxdamage1 libxext6 \
    libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2 libxshmfence1 \
    libglib2.0-0 fonts-liberation fonts-unifont ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir flask==3.0.3 playwright==1.49.1
RUN playwright install chromium

WORKDIR /app
COPY renderer.py .

EXPOSE 8080
CMD ["python", "renderer.py"]