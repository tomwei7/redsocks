FROM debian:bullseye as build
RUN set -x \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends --no-install-suggests build-essential libevent-dev libssl-dev
COPY . /redsocks
WORKDIR /redsocks
RUN set -x \
	&& make -j$(nproc)

FROM debian:bullseye
RUN set -x \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends --no-install-suggests libevent-core-2.1-7 libevent-extra-2.1-7 libssl1.1
COPY --from=build /redsocks/redsocks2 /usr/bin/redsocks2
COPY --from=build /redsocks/docker/redsocks.conf /etc/redsocks.conf
CMD ["/usr/bin/redsocks2", "-c", "/etc/redsocks.conf"]
