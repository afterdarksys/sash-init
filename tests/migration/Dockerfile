FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go test ./internal/migrate && go build -o /sahinit ./cmd/sahinit

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
COPY --from=build /sahinit /usr/local/bin/sahinit
COPY tests/migration /tests
ENTRYPOINT ["python3", "/tests/smoke.py"]
