FROM golang:1.19

WORKDIR /secretum

COPY . .

RUN go mod download

RUN go build

EXPOSE 8080

CMD ["./secretumserver"]
