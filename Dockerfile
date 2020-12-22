FROM ubuntu
COPY . /usr/src/
WORKDIR /usr/src/
RUN apt-get update && apt-get install -y \
    g++ \
    make \
    openssl \
    libssl-dev
RUN make server
WORKDIR /usr/src/msg_server_sandbox
EXPOSE 4399
CMD [ "./server.out" ]