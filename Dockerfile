FROM golang:latest
RUN curl https://glide.sh/get | sh
WORKDIR $GOPATH/src/intomy.land/kube-ldap
COPY glide.yaml glide.lock $GOPATH/src/intomy.land/kube-ldap/
RUN glide install
COPY . $GOPATH/src/intomy.land/kube-ldap
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o app .


FROM scratch
WORKDIR /root/
COPY --from=0 /go/src/intomy.land/kube-ldap/app .
EXPOSE 8000
CMD ["./app"]
