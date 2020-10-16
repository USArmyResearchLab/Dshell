FROM python:3-alpine as builder

COPY . /src

WORKDIR /src

ARG BUILD_DEPS="curl gcc g++ libpcap-dev"
ARG OUI_SRC="http://standards-oui.ieee.org/oui.txt"

RUN apk add --no-cache ${BUILD_DEPS} && python -m venv "/opt/venv"

RUN curl --location --silent --output "/src/dshell/data/oui.txt" "${OUI_SRC}"

ENV PATH="/opt/venv/bin:${PATH}"

RUN pip install --upgrade pip wheel && pip install --use-feature=2020-resolver .

FROM python:3-alpine

ARG RUN_DEPS="bash libstdc++ libpcap"

COPY --from=builder /opt/venv /opt/venv

RUN apk add --no-cache ${RUN_DEPS}

VOLUME ["/data"]

WORKDIR "/data"

ENV PATH="/opt/venv/bin:${PATH}"

ENTRYPOINT ["dshell"]
