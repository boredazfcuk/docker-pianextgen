FROM alpine:3.13
MAINTAINER boredazfcuk

# Container version serves no real purpose. Increment to force a container rebuild.
ARG container_version="1.0.1"
ARG app_dependencies="openvpn curl jq openvpn conntrack-tools ulogd coreutils"
ENV config_dir="/config" \
   app_base_dir="/PIANextGen"

RUN echo "$(date '+%d/%m/%Y - %H:%M:%S') | ***** BUILD STARTED FOR PIA NEXT GEN OPENVPN *****" && \
echo "$(date '+%d/%m/%Y - %H:%M:%S') | Install application dependencies" && \
   apk add --no-cache --no-progress ${app_dependencies}

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY healthcheck.sh /usr/local/bin/healthcheck.sh

RUN echo "$(date '+%d/%m/%Y - %H:%M:%S') | Set permissions on scripts" && \
   chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/healthcheck.sh && \
echo "$(date '+%d/%m/%Y - %H:%M:%S') | ***** BUILD COMPLETE *****"

HEALTHCHECK --start-period=10s --interval=1m --timeout=10s \
  CMD /usr/local/bin/healthcheck.sh
  
VOLUME "${config_dir}"
WORKDIR "${app_base_dir}"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
