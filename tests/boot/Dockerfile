FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /sahinit ./cmd/sahinit && CGO_ENABLED=0 go build -o /probe ./tests/boot/probe

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends linux-image-cloud-amd64 cpio && rm -rf /var/lib/apt/lists/*
COPY --from=build /sahinit /assets/sahinit
COPY --from=build /probe /assets/probe
COPY tests/boot/make-images.sh /make-images.sh
ENTRYPOINT ["sh", "/make-images.sh"]
