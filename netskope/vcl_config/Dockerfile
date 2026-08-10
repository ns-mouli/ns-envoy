FROM ubuntu:20.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY envoy /opt/envoy-vcl/bin/envoy
RUN chmod +x /opt/envoy-vcl/bin/envoy

COPY vcl.conf /etc/service_conf/vcl.conf
COPY envoy.yaml /etc/service_conf/envoy.yaml
COPY qosmos_protocols.json /etc/service_conf/qosmos_protocols.json
COPY liveness_check /usr/local/bin/liveness_check
RUN chmod +x /usr/local/bin/liveness_check

RUN printf '#!/bin/bash\n\
until [ -S /run/vpp/app_ns_sockets/default ]; do sleep 1; done\n\
chmod 666 /run/vpp/app_ns_sockets/default 2>/dev/null || true\n\
until [ -f /run/vpp/envoy_app_attached ]; do sleep 1; done\n\
export VCL_CONFIG=/etc/service_conf/vcl.conf\n\
exec /opt/envoy-vcl/bin/envoy -c /etc/service_conf/envoy.yaml \\\n\
  --disable-hot-restart --concurrency 2\n' > /usr/local/bin/start_envoyvcl.sh && chmod +x /usr/local/bin/start_envoyvcl.sh

CMD ["/usr/local/bin/start_envoyvcl.sh"]
