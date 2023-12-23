FROM scratch

COPY ./ip-masq-agent /bin/ip-masq-agent

ENTRYPOINT ["/bin/ip-masq-agent"]
