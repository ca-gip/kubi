FROM golang:latest
RUN curl https://glide.sh/get | sh
WORKDIR $GOPATH/src/github.com/ca-gip/kubi
COPY . $GOPATH/src/github.com/ca-gip/kubi
RUN make dep
RUN make linux
RUN make test


FROM alpine
WORKDIR /root/
COPY --from=0 /go/src/github.com/ca-gip/kubi/build/kubi .
EXPOSE 8000
CMD ["./kubi"]
