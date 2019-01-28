FROM golang:latest
RUN curl https://glide.sh/get | sh
WORKDIR $GOPATH/src/github.com/ca-gip/kubi
COPY . $GOPATH/src/github.com/ca-gip/kubi
RUN glide install
RUN make test
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/kubi .


FROM scratch
WORKDIR /root/
COPY --from=0 /go/src/github.com/ca-gip/kubi/bin/kubi .
EXPOSE 8000
CMD ["./kubi"]
