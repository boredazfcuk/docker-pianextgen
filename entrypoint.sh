#!/bin/ash

##### Functions #####
Initialise(){
   certificate_path="${app_base_dir}/ca.rsa.4096.crt"
   echo
   echo "$(date '+%c') ***** Starting Private Internet Access Next Gen OpenVPN container *****"
   echo "$(date '+%c') $(cat /etc/*-release | grep "PRETTY_NAME" | sed 's/PRETTY_NAME=//g' | sed 's/"//g')"
   echo "$(date '+%c') Configuration directory: ${config_dir}"
   echo "$(date '+%c') Application directory: ${app_base_dir}"
   if [ ! -f "${app_base_dir}/pia_config.ovpn" ]; then
      echo "$(date '+%c') Download PIA Next Gen OpenVPN strong encryption configuration file"
      wget -qO "${app_base_dir}/strong.ovpn" "https://raw.githubusercontent.com/pia-foss/manual-connections/master/openvpn_config/strong.ovpn"
   fi
   if [ ! -f "${certificate_path}" ]; then
      echo "$(date '+%c') Download PIA certification authority certificate"
      wget -qO "${certificate_path}" "https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt"
   fi
   if [ "${pia_username}" ] && [ "${pia_password}" ]; then
      echo "${pia_username}" > "${config_dir}/auth.conf"
      echo "${pia_password}" >> "${config_dir}/auth.conf"
      echo "$(date '+%c') PIA username: ${pia_username}"
      echo "$(date '+%c') PIA password: ${pia_password}"
      echo "$(date '+%c') Credentials saved to ${config_dir}/auth.conf"
      echo "$(date '+%c') Please recreate container without these variables specified"
      chown 600 
      exit 1
   fi
   pia_server_list='https://serverlist.piaservers.net/vpninfo/servers/v4'
   echo "$(date '+%c') Server list location: ${pia_server_list}"
   if [ -f "${config_dir}/auth.conf" ]; then
      pia_username="$(head -1 "${config_dir}/auth.conf")"
      pia_password="$(tail -1 "${config_dir}/auth.conf")"
   else
      echo "$(date '+%c') Authentication information file does not exist: ${config_dir}/auth.conf"
      echo "$(date '+%c') Cannot continue. Exiting"
      sleep 120
      exit 1
   fi
   pia_use_dns="false"
   pia_use_port_forward="true"
   pia_protocol="udp"
   pia_encryption="strong"
   pia_port="1197"
   if [ "${endpoint_override}" ]; then echo "$(date '+%c') Server auto-selection disabled. Configured VPN endpoint: ${endpoint_override}"; else endpoint_override="False"; fi
   echo "$(date '+%c') PIA username: ${pia_username}"
   echo "$(date '+%c') PIA password: ${pia_password}"
   echo "$(date '+%c') Use PIA DNS: ${pia_use_dns}"
   echo "$(date '+%c') Configure port forwarding: ${pia_use_port_forward}"
   echo "$(date '+%c') Network protocol: ${pia_protocol}"
   echo "$(date '+%c') Network port: ${pia_port}"
   echo "$(date '+%c') Encryption type: ${pia_encryption}"
   echo "$(date '+%c') Maximum latency: ${maximum_latency:=0.05}"
   echo "$(date '+%c') Creating connection script: ${app_base_dir}/pia_connect.sh"
   {
      echo '#!/bin/ash'
      echo 'echo $route_vpn_gateway > '"${app_base_dir}"'/default_gateway'
   } >"${app_base_dir}/pia_connect.sh"
   chmod +x "${app_base_dir}/pia_connect.sh"
   echo "$(date '+%c') Creating disconnect script: ${app_base_dir}/pia_disconnect.sh"
   {
      echo '#!/bin/ash'
      echo 'rm -rf /run/pia.pid '"${app_base_dir}"'/default_gateway'
   } >"${app_base_dir}/pia_disconnect.sh"
   chmod +x "${app_base_dir}/pia_disconnect.sh"
}

CreateTunnelAdapter(){
   if [ ! -d "/dev/net" ]; then echo "$(date '+%c') Creating network device classification in /dev"; mkdir /dev/net; fi
   if [ ! -c "/dev/net/tun" ]; then
      echo "$(date '+%c') Creating VPN tunnel adapter"
      mknod -m 0666 /dev/net/tun c 10 200
   fi
}

ConfigureLogging(){
   echo "$(date '+%c') Logging to ${config_dir}/log/iptables.log"
   sed -i -e "s%^#plugin=\"/usr/lib/ulogd/ulogd_inppkt_NFLOG.so\"%plugin=\"/usr/lib/ulogd/ulogd_inppkt_NFLOG.so\"%" \
      -e "s%^#plugin=\"/usr/lib/ulogd/ulogd_raw2packet_BASE.so\"%plugin=\"/usr/lib/ulogd/ulogd_raw2packet_BASE.so\"%" \
      -e "s%^#plugin=\"/usr/lib/ulogd/ulogd_filter_IFINDEX.so\"%plugin=\"/usr/lib/ulogd/ulogd_filter_IFINDEX.so\"%" \
      -e "s%^#plugin=\"/usr/lib/ulogd/ulogd_filter_IP2STR.so\"%plugin=\"/usr/lib/ulogd/ulogd_filter_IP2STR.so\"%" \
      -e "s%^#plugin=\"/usr/lib/ulogd/ulogd_filter_PRINTPKT.so\"%plugin=\"/usr/lib/ulogd/ulogd_filter_PRINTPKT.so\"%" \
      -e "s%^#plugin=\"/usr/lib/ulogd/ulogd_output_LOGEMU.so\"%plugin=\"/usr/lib/ulogd/ulogd_output_LOGEMU.so\"%" \
      -e 's/^#stack=log1:NFLOG,base1/stack=log1:NFLOG,base1/' \
      -e 's/ulogd_syslogemu.log/iptables.log/' /etc/ulogd.conf
   if [ ! -d "${config_dir}/log" ]; then mkdir -p "${config_dir}/log"; fi
   if [ ! -f "${config_dir}/log/iptables.log" ]; then touch "${config_dir}/log/iptables.log"; fi
   if [ -f "/var/log/iptables.log" ]; then rm "/var/log/iptables.log"; fi
   if [ ! -L "/var/log/iptables.log" ]; then ln -s "${config_dir}/log/iptables.log" "/var/log/iptables.log"; fi
   /usr/sbin/ulogd 2>/dev/null &
   if [ "${follow_iptables_log}" ]; then
      tail -Fn0 "${config_dir}/log/iptables.log" &
   fi
}

GetServerList(){
   echo "$(date '+%c') Get server list... "
   full_region_data="$(curl --silent "$pia_server_list" | head -1)"
   if [ "${#full_region_data}" -lt 1000 ]; then
     echo "$(date '+%c') Could not get correct region data. Exiting"
      sleep 120
     exit 1
   fi
}

GetServerLatency() {
   server_ip="$(echo "$1" | awk 'BEGIN { FS = "," } ; {print $1}')"
   region_id="$(echo "$1" | awk 'BEGIN { FS = "," } ; {print $2}')"
   region_name="$(echo "$1" | awk 'BEGIN { FS = "," } ; {print $3}')"
   time=$(LC_NUMERIC=en_US.utf8 curl --output /dev/null --silent --connect-timeout ${maximum_latency} --write-out "%{time_connect}" http://${server_ip}:443)
   if [ $? -eq 0 ]; then
      # Return reults from function
      echo "Got latency ${time}s for $region_name:$region_id"
      # Print results to screen
      >&2 echo "Got latency ${time}s for $region_name (Region ID: $region_id)"
   fi
}

CheckLatency(){
   echo "$(date '+%c') Check latency of servers which allow port forwarding"
   selected_region_data=$(echo $full_region_data | jq -r '.regions[] | select(.port_forward==true) | .servers.meta[0].ip+","+.id+","+.name+","+(.geo|tostring)')
   echo "$(date '+%c') Test regions that are quicker than ${maximum_latency} seconds:"
   OLDIFS="${IFS}"
   IFS=$'\n'
   region_list="$(for line in $selected_region_data; do GetServerLatency "$line"; done)"
   IFS="${OLDIFS}"
}

DetermineFastestServer(){
   fastest_region="$(echo "${region_list}" | sort | head -1 | awk 'BEGIN { FS = ":" } ; {print $2}')"
   if [ -z "${fastest_region}" ]; then
      echo "$(date '+%c') No region responded within ${maximum_latency} seconds. Exiting"
      sleep 120
      exit 1
   else
      echo "$(date '+%c') Fastest region is: ${fastest_region}"
   fi
}

GetEndpointInfo(){
   selected_region_data="$(echo "${full_region_data}" | jq --arg NAME "${fastest_region}" -r '.regions[] | select(.id==$NAME)')"
   echo "$(date '+%c') The selected server is $(echo ${selected_region_data} | jq -r '.name')"
   selected_server_meta_ip="$(echo ${selected_region_data} | jq -r '.servers.meta[0].ip')"
   selected_server_meta_hostname="$(echo ${selected_region_data} | jq -r '.servers.meta[0].cn')"
   selected_server_ip="$(echo ${selected_region_data} | jq -r '.servers.ovpnudp[0].ip')"
   selected_server_hostname="$(echo ${selected_region_data} | jq -r '.servers.ovpnudp[0].cn')"
   echo "$(date '+%c') Selected server meta IP: ${selected_server_meta_ip}"
   echo "$(date '+%c') Selected server meta hostname: ${selected_server_meta_hostname}"
   echo "$(date '+%c') Selected server IP: ${selected_server_ip}"
   echo "$(date '+%c') Selected server hostname: ${selected_server_hostname}"
}

GetToken(){
   echo "$(date '+%c') Get token from meta service..."
   token_response="$(curl --silent --user "${pia_username}:${pia_password}" --connect-to "${selected_server_meta_hostname}::${selected_server_meta_ip}:" --cacert "${certificate_path}" "https://${selected_server_meta_hostname}/authv3/generateToken")"
   if [ "$(echo "${token_response}" | jq -r '.status')" != "OK" ]; then
      echo "$(date '+%c') Could not get a token. Exiting"
      sleep 120
      exit 1
   fi
   pia_token="$(echo "${token_response}" | jq -r '.token')"
   echo "$(date '+%c') Token received: ${pia_token}"
}

SetConfig(){
   echo "$(date '+%c') Create token file and set permissions"
   {
      echo "${pia_token:0:62}"
      echo "${pia_token:62}"
   } > "${config_dir}/token.conf"
   chmod 600 "${config_dir}/token.conf"
   echo "$(date '+%c') Reset config file: ${config_dir}/pia_config.ovpn"
   cat "${app_base_dir}/strong.ovpn" > "${config_dir}/pia_config.ovpn"
   echo "$(date '+%c') Add selected server to config file: ${selected_server_hostname}"
   echo "remote ${selected_server_ip} ${pia_port} ${pia_protocol}" >> "${config_dir}/pia_config.ovpn"
   echo "$(date '+%c') Set token file location: ${config_dir}/token.conf"
   sed -i "s%^auth-user-pass .*%auth-user-pass ${config_dir}/token.conf%" "${config_dir}/pia_config.ovpn"
   echo "$(date '+%c') Set tunnel adapter name to tun0"
   sed -i "s%^dev tun.*%dev tun0%" "${config_dir}/pia_config.ovpn"
   echo "$(date '+%c') Set connection script location: ${app_base_dir}/pia_connect.sh"
   sed -i "s%^up .*%up ${app_base_dir}/pia_connect.sh%" "${config_dir}/pia_config.ovpn"
   echo "$(date '+%c') Set disconnection script location: ${app_base_dir}/pia_disconnect.sh"
   sed -i "s%^down .*%down ${app_base_dir}/pia_disconnect.sh%" "${config_dir}/pia_config.ovpn"
}

ClearAllRules(){
   echo "$(date '+%c') Clear iptables configuration"
   conntrack -F >/dev/null 2>&1
   iptables -F
   iptables -X
}

SetDefaultPolicies(){
   echo "$(date '+%c') Set default policies"
   iptables -P INPUT ACCEPT
   iptables -P FORWARD ACCEPT
   iptables -P OUTPUT ACCEPT
}

CreateLoggingRules(){
   echo "$(date '+%c') Create logging chains"
   iptables -N LOG_IN
   iptables -N LOG_FW
   iptables -N LOG_OUT

   echo "$(date '+%c') Create chain rules"
   iptables -A LOG_IN -j NFLOG --nflog-group 0 --nflog-prefix "IN DENY   : "
   iptables -A LOG_IN -j DROP
   iptables -A LOG_FW -j NFLOG --nflog-group 0 --nflog-prefix "FW DENY   : "
   iptables -A LOG_FW -j DROP
   iptables -A LOG_OUT -j NFLOG --nflog-group 0 --nflog-prefix "OUT ALLOW : "
   iptables -A LOG_OUT -j ACCEPT

   echo "$(date '+%c') Enable chains"
   iptables -A INPUT -j LOG_IN
   iptables -A FORWARD -j LOG_FW
   iptables -A OUTPUT -j LOG_OUT
}

LoadPretunnelRules(){
   echo "$(date '+%c') Load pre-tunnel rules"

   echo "$(date '+%c') Allow established and related traffic"
   iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
   iptables -I FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
   iptables -I OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

   echo "$(date '+%c') Allow loopback traffic"
   iptables -I INPUT -i lo -j ACCEPT
   iptables -I OUTPUT -o lo -j ACCEPT

   echo "$(date '+%c') Allow LAN ping"
   iptables -I INPUT -i "${lan_adapter}" -s "${docker_lan_ip_subnet}" -d "${lan_ip}" -p icmp -j ACCEPT
   iptables -I INPUT -i "${lan_adapter}" -s "${host_lan_ip_subnet}" -d "${lan_ip}" -p icmp -j ACCEPT

   echo "$(date '+%c') Allow outgoing DNS traffic to host network over LAN adapter"
   iptables -I OUTPUT -o "${lan_adapter}" -s "${lan_ip}" -d "${host_lan_ip_subnet}" -p udp --dport 53 -j ACCEPT
   iptables -I OUTPUT -o "${lan_adapter}" -s "${lan_ip}" -d "${host_lan_ip_subnet}" -p tcp --dport 53 -j ACCEPT

   echo "$(date '+%c') Allow OpenVPN port: ${vpn_port}"
   iptables -I OUTPUT -o "${lan_adapter}" -s "${lan_ip}" -p udp --dport "${vpn_port}" -j ACCEPT
   iptables -I INPUT -i "${lan_adapter}" -d "${lan_ip}" -p udp --sport "${vpn_port}" -j ACCEPT
}

LoadPosttunnelRules(){
   echo "$(date '+%c') Load post-tunnel rules"

   echo "$(date '+%c') Allow payload and signature retrieval from PIA port forwarding server"
   iptables -I OUTPUT -o "${vpn_adapter}" -s "${vpn_ip}" -p tcp --dport 19999 -j ACCEPT

   echo "$(date '+%c') Allow ping from Docker LAN subnet to be forwarded from LAN to VPN"
   iptables -I FORWARD -i "${lan_adapter}" -o "${vpn_adapter}" -s "${docker_lan_ip_subnet}" -p icmp -j ACCEPT

   echo "$(date '+%c') Allow pong to Docker LAN subnet to be forwarded from VPN to LAN"
   iptables -I FORWARD -i "${vpn_adapter}" -o "${lan_adapter}" -d "${docker_lan_ip_subnet}" -p icmp -j ACCEPT

   echo "$(date '+%c') Allow ping from Host LAN subnet to be forwarded from LAN to VPN"
   iptables -I FORWARD -i "${lan_adapter}" -o "${vpn_adapter}" -s "${host_lan_ip_subnet}" -p icmp -j ACCEPT

   echo "$(date '+%c') Allow pong to Host LAN subnet to be forwarded from VPN to LAN"
   iptables -I FORWARD -i "${vpn_adapter}" -o "${lan_adapter}" -d "${host_lan_ip_subnet}" -p icmp -j ACCEPT

   echo "$(date '+%c') Allow DNS requests from Docker LAN subnet to be forwarded from LAN to VPN"
   iptables -I FORWARD -i "${lan_adapter}" -o "${vpn_adapter}" -s "${docker_lan_ip_subnet}" -p udp --dport 53 -j ACCEPT

   echo "$(date '+%c') Allow DNS replies to Docker LAN subnet to be forwarded from VPN to LAN"
   iptables -I FORWARD -i "${vpn_adapter}" -o "${lan_adapter}" -d "${docker_lan_ip_subnet}" -p udp --sport 53 -j ACCEPT

   echo "$(date '+%c') Allow HTTP requests from Docker LAN subnet to be forwarded from LAN to VPN"
   iptables -I FORWARD -i "${lan_adapter}" -o "${vpn_adapter}" -s "${docker_lan_ip_subnet}" -p tcp --dport 80 -j ACCEPT

   echo "$(date '+%c') Allow HTTP replies to Docker LAN subnet to be forwarded from VPN to LAN"
   iptables -I FORWARD -i "${vpn_adapter}" -o "${lan_adapter}" -d "${docker_lan_ip_subnet}" -p tcp --sport 80 -j ACCEPT

   echo "$(date '+%c') Allow HTTPS requests from Docker LAN subnet to be forwarded from LAN to VPN"
   iptables -I FORWARD -i "${lan_adapter}" -o "${vpn_adapter}" -s "${docker_lan_ip_subnet}" -p tcp --dport 443 -j ACCEPT

   echo "$(date '+%c') Allow HTTPS replies to Docker LAN subnet to be forwarded from VPN to LAN"
   iptables -I FORWARD -i "${vpn_adapter}" -o "${lan_adapter}" -d "${docker_lan_ip_subnet}" -p tcp --sport 443 -j ACCEPT

   echo "$(date '+%c') Allow non-routable UPnP traffic from VPN adapter"
   iptables -I INPUT -i "${vpn_adapter}" -s "${vpn_ip}" -d 239.255.255.250 -p udp --dport 1900 -j ACCEPT

   echo "$(date '+%c') Allow local peer discovery"
   iptables -I INPUT -i "${vpn_adapter}" -s "${vpn_ip}" -d 239.192.152.143 -p udp --dport 6771 -j ACCEPT

   echo "$(date '+%c') Disable multicast"
   iptables -I OUTPUT -o "${vpn_adapter}" -s "${vpn_ip}" -d 224.0.0.0/24 -p igmp -j DROP

   echo "$(date '+%c') Allow web traffic out"
   iptables -I OUTPUT -o "${vpn_adapter}" -s "${vpn_ip}" -p tcp --dport 80 -j ACCEPT
   iptables -I OUTPUT -o "${vpn_adapter}" -s "${vpn_ip}" -p tcp --dport 443 -j ACCEPT

   echo "$(date '+%c') Allow traceroute traffic from VPN IP to VPN default gateway out via VPN adapter"
   iptables -I OUTPUT -o "${vpn_adapter}" -s "${vpn_ip}" -d "${vpn_default_gateway}" -p udp --dport 33434:33534 -j ACCEPT

   echo "$(date '+%c') Allow outgoing requests from Docker LAN subnet to be forwarded from LAN to VPN"
   iptables -I INPUT -i "${lan_adapter}" -d "${lan_ip}" -p udp -j ACCEPT
   iptables -I FORWARD -i "${lan_adapter}" -o "${vpn_adapter}" -s "${docker_lan_ip_subnet}" -p udp --sport 57700 -j ACCEPT
   iptables -I FORWARD -i "${lan_adapter}" -o "${lan_adapter}" -s "${docker_lan_ip_subnet}" -p udp --sport 57700 -j ACCEPT
   iptables -I FORWARD -i "${vpn_adapter}" -o "${lan_adapter}" -d "${docker_lan_ip_subnet}" -p udp --sport 6881 --dport 57700 -j ACCEPT
   iptables -I FORWARD -i "${lan_adapter}" -o "${vpn_adapter}" -s "${docker_lan_ip_subnet}" -p tcp --sport 58800:59900 -j ACCEPT

   echo "$(date '+%c') Allow HTTP traffic from Docker network to local web server"
   iptables -I INPUT -i "${lan_adapter}" -s "${docker_lan_ip_subnet}" -d "${lan_ip}" -p tcp --dport 80 -j ACCEPT
}

GetLANInfo(){
   lan_ip="$(hostname -i)"
   host_network_route="${lan_ip%.*}.1"
   broadcast_address="$(ip -4 addr | grep "${lan_ip}" | awk '{print $4}')"
   docker_lan_ip_subnet="$(ip -4 route | grep "${lan_ip}" | grep -v via | awk '{print $1}')"
   lan_adapter="$(ip -o addr | grep eth. | awk '{print $2}')"
   vpn_port="$(grep "^remote " "${config_dir}/pia_config.ovpn" | awk '{print $3}')"
   echo "$(date '+%c') LAN Adapter: ${lan_adapter}"
   echo "$(date '+%c') LAN IP Address: ${lan_ip}"
   echo "$(date '+%c') Host network: ${host_lan_ip_subnet}"
   echo "$(date '+%c') Route to host network: ${host_network_route}"
   echo "$(date '+%c') Docker network: ${docker_lan_ip_subnet}"
   echo "$(date '+%c') Docker network broadcast address: ${broadcast_address}"
}

GetVPNInfo(){
   vpn_cidr_ip="$(ip -o addr | grep tun. | awk '{print $4}')"
   vpn_ip="${vpn_cidr_ip%/*}"
   vpn_adapter="$(ip -o addr | grep tun. | awk '{print $2}')"
   vpn_default_gateway="$(route | grep tun.$ | grep default | awk '{print $2}')"
   echo "$(date '+%c') VPN Info: ${vpn_adapter} ${vpn_cidr_ip} ${vpn_ip} ${vpn_port}"
   echo "$(date '+%c') Enable NAT on VPN adapter"
   iptables -t nat -A POSTROUTING -o "${vpn_adapter}" -j MASQUERADE
}

ConnectPIANextGenVPN(){
   default_gateway="$(ip route | grep "^default" | awk '{print $3}')"
   echo "$(date '+%c') Default gateway: ${default_gateway}"
   echo "$(date '+%c') Create additional route to Docker host network ${host_lan_ip_subnet} via ${default_gateway}"
   ip route add "${host_lan_ip_subnet}" via "${default_gateway}"
   connection_timeout=120
   echo "$(date '+%c') Starting PIA Next Gen OpenVPN connection..."
   /usr/sbin/openvpn --daemon --config "${config_dir}/pia_config.ovpn" --writepid "/run/pia.pid" --log "/var/log/pia_openvpn.log"
   echo "$(date '+%c') Wait for tunnel adapter to be created "
   while [ -z "$(ip addr | grep tun. | grep inet | awk '{print $2}')" ]; do sleep 1; done
   echo "$(date '+%c') OpenVPN Private Internet Access tunnel connected on IP: $(ip ad | grep tun. | grep inet | awk '{print $2}')"
   network_status="$(ip -o addr | grep -c tun.)"
   while [ "${network_status}" -eq 0 ] && [ "${connection_timeout}" -ne 0 ]; do
      sleep 1
      network_status="$(ip -o addr | grep -c tun.)"
      connection_timeout=$((connection_timeout - 1))
   done
   if [ "${connection_timeout}" -eq 0 ]; then
      echo "$(date '+%c') Connection timeout. Exiting"
      sleep 120
      exit 1
   else
      public_ip="$(wget -qO- icanhazip.com)"
      echo "$(date '+%c') Tunnel up. Public IP: ${public_ip}"
   fi
   ovpn_pid="$(cat /run/pia.pid)"
   gateway_ip="$(cat ${app_base_dir}/default_gateway)"
   echo "$(date '+%c') OpenVPN Process ID: ${ovpn_pid}"
   echo "$(date '+%c') VPN route IP: ${gateway_ip}"
}

GetPortForwardingPayloadAndSignature(){
   echo "$(date '+%c') Getting signature..."
   payload_and_signature="$(curl --get --silent --max-time 5 --show-error \
      --connect-to "${selected_server_hostname}::${gateway_ip}:" \
      --cacert "${certificate_path}" \
      --data-urlencode "token=${pia_token}" \
      "https://${selected_server_hostname}:19999/getSignature")"
   if [ "$(echo "${payload_and_signature}" | jq -r '.status')" != "OK" ]; then
      echo "$(date '+%c') Failed to retrieve signature"
      sleep 120
      exit 1
   fi
}

ConfigurePortForwarding(){
   iptables_port="0"
   signature="$(echo "${payload_and_signature}" | jq -r '.signature')"
   payload="$(echo "${payload_and_signature}" | jq -r '.payload')"
   forwarded_port="$(echo "${payload}" | base64 -d | jq -r '.port')"
   expiry_time="$(echo "${payload}" | base64 -d | jq -r '.expires_at')"
   echo "$(date '+%c') Port is ${forwarded_port} and it will expire on ${expiry_time}"
   while true; do
      bind_port_response="$(curl --get --silent --max-time 5 --show-error \
         --connect-to "${selected_server_hostname}::${gateway_ip}:" \
         --cacert "${certificate_path}" \
         --data-urlencode "payload=${payload}" \
         --data-urlencode "signature=${signature}" \
         "https://${selected_server_hostname}:19999/bindPort")"
      if [ "$(echo "${bind_port_response}" | jq -r '.status')" != "OK" ]; then
         echo "The API did not return OK when trying to bind port. Exiting."
         sleep 120
         exit 1
      fi
      echo "$(date '+%c') Port ${forwarded_port} refreshed on $(date)."
      echo "$(date '+%c') This port will expire on $(date --date="${expiry_time}")"
      if [ "${iptables_port}" != "${forwarded_port}" ]; then
         echo "$(date '+%c') Allow incoming traffic on ${vpn_ip}:${forwarded_port}"
         iptables -I INPUT -i "${vpn_adapter}" -d "${vpn_ip}" -p tcp --dport "${forwarded_port}" -j ACCEPT
         deluge_ip="$(getent hosts deluge | awk '{print $1}')"
         echo "$(date '+%c') Configure iptables rules for portforwarding to Deluge: ${deluge_ip}"
         iptables -t nat -A PREROUTING -i "${vpn_adapter}" -p tcp --sport "${forwarded_port}" --dport 57700 -j DNAT --to-destination "${deluge_ip}"
         iptables -I INPUT -i "${vpn_adapter}" -d "${vpn_ip}" -p tcp --dport "${forwarded_port}" -j ACCEPT
         echo "$(date '+%c') Forwarding ${vpn_ip}:${forwarded_port} to Deluge ${deluge_ip}:57700"
         echo "$(date '+%c') Forwarded port publically available at IP ${public_ip}:${forwarded_port}"
         iptables_port="${forwarded_port}"
      fi
      # sleep 15 minutes
      sleep 900
   done
}

##### Start Script #####
Initialise
CreateTunnelAdapter
ConfigureLogging
GetLANInfo
ClearAllRules
SetDefaultPolicies
CreateLoggingRules
LoadPretunnelRules
GetServerList
if [ "${endpoint_override}" = "False" ]; then
   CheckLatency
   DetermineFastestServer
else
   echo "$(date '+%c') Server auto-selection overide enabled"
   fastest_region="${endpoint_override}"
fi
GetEndpointInfo
GetToken
SetConfig
ConnectPIANextGenVPN
GetVPNInfo
LoadPosttunnelRules
GetPortForwardingPayloadAndSignature
ConfigurePortForwarding
echo "$(date '+%c') ***** Startup of Private Internet Access Next Gen OpenVPN container complete *****"
while [ "$(ip addr | grep tun. | grep inet | awk '{print $2}')" ]; do sleep 120; done
echo "$(date '+%c') ***** Connection dropped. Restarting container *****"