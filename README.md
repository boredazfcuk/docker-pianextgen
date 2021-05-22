# docker-pianextgen
Beta - An Alpine Linux Docker container for Private Internet Access's Next Generation servers OpenVPN client

This container is currently work in progress and is used to forward packets from other containers in the same stack to the internet. It also supports por forwarding, to another container in the stack.

## MANDATORY VARIABLES

Note: Both of the following two mandatory variables are only needed the first time the container is run. It will then save both the username and password to the file /config/auth.conf and then remove group and public permissions. Once this has been done, the container should be destroyed and recreated. This is so the password cannot be retrieved by viewing the running container's config. If you do not remove these variables, you will receive a warning each time the container is started.

pia_user: This is the username for your Private Internet Access account

pia_password: This is the password for the account named above

## OPTIONAL VARIABLES

LOGGING: If this variable is set to 'True' then the container will output the contents of the /var/log/iptables.log file to standard output. It will show all the dopped packets and is useful when debugging firewall rules

## VOLUME CONFIGURATION

A single named volume, or bind mount to a drectory on the host, is required and it should be mounted to the /config directory inside the container. This directory will be used to store the auth.conf username/password file.

## IPTABLES CONFIGURATION

Currently the container will create a default iptables configuration each time the container is launched.

Litecoin: LfmogjcqJXHnvqGLTYri5M8BofqqXQttk4