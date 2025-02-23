FROM golang:1.20 as build
WORKDIR /src
COPY ./ .
RUN CGO_ENABLED=0 GOOS=linux go build -o api /src/cmd/main.go

FROM alpine
WORKDIR /opt/bin
COPY --from=build /src/api .
ENTRYPOINT ["./api"]
