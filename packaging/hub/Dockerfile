FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/xtop .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/xtop /usr/local/bin/xtop
EXPOSE 9200
ENTRYPOINT ["/usr/local/bin/xtop"]
CMD ["hub"]
