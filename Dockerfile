# Stage 1: Build
FROM golang:1.26-bookworm AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /ssh_session_exporter .

# Stage 2: Runtime
FROM gcr.io/distroless/static-debian12
COPY --from=builder /ssh_session_exporter /usr/local/bin/ssh_session_exporter
EXPOSE 9842
ENTRYPOINT ["/usr/local/bin/ssh_session_exporter"]
