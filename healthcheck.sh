#!/bin/ash

tunnel_adapter_count="$(ip -o -4 addr | grep -c tun.)"

if [ "${tunnel_adapter_count}" -ne 1 ]; then
   echo "Tunnel does not exist"
   exit 1
fi

tunnel_adapter="$(ip -o addr | grep tun. | awk '{print $2}')"
tunnel_adapter_cidr="$(ip -o addr | grep tun. | awk '{print $4}')"
tunnel_adapter_ip="${tunnel_adapter_cidr%/*}"
tunnel_default_gateway="$(route | grep tun.$ | grep default | awk '{print $2}')"
if [ "$(traceroute -m1 -i "${tunnel_adapter}" -s "${tunnel_adapter_ip}" -w 1 "${tunnel_default_gateway}" | grep -c "ms")" -ne 1 ]; then
   echo "Cannot contact default gateway. Tunnel down"
   exit 1
fi
echo "Tunnel adapter present and default gateway responding"
exit 0