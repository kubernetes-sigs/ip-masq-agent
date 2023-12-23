FROM scratch

COPY ./ip-masq-agent-stub /bin/ip-masq-agent

ENTRYPOINT ["/bin/ip-masq-agent"]
