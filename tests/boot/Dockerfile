FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /sahinit ./cmd/sahinit && CGO_ENABLED=0 go build -o /probe ./tests/boot/probe && CGO_ENABLED=0 go build -o /sashfix ./tests/boot/sashfix
# The sash binary comes from the sash repository, which test-boot.py passes
# as the named build context "sash" (read-only; nothing there is changed).
COPY --from=sash . /sash-src
RUN cd /sash-src && CGO_ENABLED=0 GOFLAGS=-buildvcs=false go build -o /sash ./cmd/sash

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends linux-image-cloud-amd64 cpio busybox-static e2fsprogs && rm -rf /var/lib/apt/lists/*
COPY --from=build /sahinit /assets/sahinit
COPY --from=build /probe /assets/probe
COPY --from=build /sashfix /assets/sashfix
COPY --from=build /sash /assets/sash
COPY tests/boot/make-images.sh /make-images.sh
COPY contrib/initramfs/init /root-init
ENTRYPOINT ["sh", "/make-images.sh"]
