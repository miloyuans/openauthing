FROM node:22-alpine

WORKDIR /workspace/web/admin

COPY web/admin/package*.json ./
RUN npm install

EXPOSE 5173
