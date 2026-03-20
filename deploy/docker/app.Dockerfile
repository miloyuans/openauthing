FROM golang:1.24-alpine

WORKDIR /workspace

COPY go.mod ./
RUN go mod download

EXPOSE 8080
