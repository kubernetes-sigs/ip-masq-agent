FROM alpine:3

RUN apk add iptables

COPY ./ip-masq-agent /bin/ip-masq-agent

ENTRYPOINT ["/bin/ip-masq-agent"]
