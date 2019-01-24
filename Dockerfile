FROM golang:latest
RUN curl https://glide.sh/get | sh
WORKDIR $GOPATH/src/intomy.land/kubi
COPY glide.yaml glide.lock $GOPATH/src/intomy.land/kubi/
RUN glide install
COPY . $GOPATH/src/intomy.land/kubi
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/kubi .


FROM scratch
WORKDIR /root/
COPY --from=0 /go/src/intomy.land/kubi/bin/kubi .
EXPOSE 8000
CMD ["./kubi"]
