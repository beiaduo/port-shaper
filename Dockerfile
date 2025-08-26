FROM golang:1.25

RUN apt-get update && apt-get install -y iproute2 iputils-ping iperf3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .
RUN go build -o port-shaper main.go

CMD ["./port-shaper"]