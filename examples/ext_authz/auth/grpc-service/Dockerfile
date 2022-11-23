FROM golang:alpine@sha256:46f1fa18ca1ec228f7ea4978ad717f0a8c5e51436e7b8efaf64011f7729886df AS builder

RUN apk --no-cache add make
COPY . /app
RUN make -C /app/grpc-service

FROM alpine@sha256:8914eb54f968791faf6a8638949e480fef81e697984fba772b3976835194c6d4

COPY --from=builder /app/grpc-service/server /app/server
CMD ["/app/server", "-users", "/etc/users.json"]
