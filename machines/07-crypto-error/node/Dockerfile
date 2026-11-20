FROM node:22-alpine

WORKDIR /app
COPY package.json .
RUN npm install --no-audit --no-fund
COPY server.js .

ENV NODE_ENV=development
EXPOSE 5000
CMD ["node", "server.js"]