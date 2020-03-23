FROM golang:latest as build
RUN curl https://glide.sh/get | sh
WORKDIR $GOPATH/src/github.com/ca-gip/kubi
COPY . $GOPATH/src/github.com/ca-gip/kubi
RUN make build


FROM scratch
WORKDIR /root/
COPY --from=build /go/src/github.com/ca-gip/kubi/build/kubi .
EXPOSE 8000
CMD ["./kubi"]
