# Pin the fcli minor version for reproducible builds; override with --build-arg FCLI_IMAGE=fortifydocker/fcli:3-ubi9.
ARG FCLI_IMAGE=fortifydocker/fcli:3.29-ubi9
FROM ${FCLI_IMAGE}

ARG COLLECTOR_VERSION=1.0.0
LABEL org.opencontainers.image.title="fortify-signalbridge-mvp" \
      org.opencontainers.image.description="One-shot Fortify SignalBridge. Collects FoD or SSC with fcli, then emits fortify.signal events." \
      org.opencontainers.image.version="${COLLECTOR_VERSION}"

ENV COLLECTOR_HOME=/opt/collector \
    COLLECTOR_VERSION=${COLLECTOR_VERSION} \
    OUTPUT_DIR=/data/out \
    TZ=UTC

USER root
COPY constraints.txt /tmp/constraints.txt
RUN dnf install -y --setopt=install_weak_deps=False python3-pyyaml python3-pip \
 && if ! dnf install -y --setopt=install_weak_deps=False python3-jsonschema \
      || ! python3 -c 'import jsonschema; raise SystemExit(0 if tuple(int(p) for p in jsonschema.__version__.split(".")[:2]) >= (4, 17) else 1)'; then \
      pip3 install --no-cache-dir --target /opt/collector/pydeps -c /tmp/constraints.txt jsonschema; \
    fi \
 && dnf clean all \
 && rm -rf /var/cache/dnf /tmp/constraints.txt
COPY actions/ /opt/collector/actions/
COPY classifiers/ /opt/collector/classifiers/
COPY schema/ /opt/collector/schema/
COPY bin/ /opt/collector/bin/
COPY signalbridge/ /opt/collector/signalbridge/
COPY rules/ /opt/collector/rules/
COPY config/ /opt/collector/config/
RUN sed -i 's/\r$//' /opt/collector/bin/*.sh /opt/collector/bin/*.py \
 && cd /opt/collector/actions \
 && sha256sum *.fcli > /opt/collector/actions.sha256 \
 && chmod 0555 /opt/collector/bin/*.sh /opt/collector/bin/*.py \
 && chmod -R a-w /opt/collector \
 && mkdir -p /data/out \
 && chown 10001:10001 /data/out

USER 10001
WORKDIR /data
VOLUME ["/data/out"]
ENV PYTHONPATH=/opt/collector/pydeps:/opt/collector
ENTRYPOINT ["/opt/collector/bin/entrypoint.sh"]
