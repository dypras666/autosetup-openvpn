#!/bin/bash

# OpenVPN Auto Setup Script for Ubuntu 20.04
# This script must be run as root

# Exit immediately if a command exits with a non-zero status
set -e

# Function to check if script is run as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root"
        exit 1
    fi
}

# Function to install required packages
install_packages() {
    apt update
    apt install -y openvpn easy-rsa
}

# Function to set up PKI and CA
setup_pki() {
    mkdir -p /etc/openvpn/easy-rsa
    cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
    cd /etc/openvpn/easy-rsa

    # Initialize the PKI
    ./easyrsa init-pki

    # Create CA (non-interactive)
    EASYRSA_BATCH=1 EASYRSA_REQ_CN="OpenVPN-CA" ./easyrsa build-ca nopass

    # Generate server certificate and key
    EASYRSA_BATCH=1 ./easyrsa build-server-full server nopass

    # Generate Diffie-Hellman parameters
    ./easyrsa gen-dh

    # Generate HMAC signature to strengthen the server's TLS integrity verification
    openvpn --genkey --secret /etc/openvpn/ta.key
}

# Function to set up server configuration
setup_server_config() {
    # Copy required files to OpenVPN directory
    cp /etc/openvpn/easy-rsa/pki/ca.crt /etc/openvpn/
    cp /etc/openvpn/easy-rsa/pki/issued/server.crt /etc/openvpn/
    cp /etc/openvpn/easy-rsa/pki/private/server.key /etc/openvpn/
    cp /etc/openvpn/easy-rsa/pki/dh.pem /etc/openvpn/

    # Create server configuration
    cat > /etc/openvpn/server.conf << EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
EOF
}

# Function to enable IP forwarding
enable_ip_forwarding() {
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-openvpn.conf
    sysctl --system
}

# Function to configure firewall
configure_firewall() {
    # Get primary network interface
    NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    
    # Configure UFW
    ufw allow OpenSSH
    ufw allow 1194/udp
    
    # Configure NAT
    sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    cat > /etc/ufw/before.rules << EOF
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
COMMIT
EOF
    
    ufw --force enable
}

# Function to generate client configuration
generate_client_config() {
    local CLIENT_NAME=$1
    
    # Generate client certificate and key
    cd /etc/openvpn/easy-rsa
    EASYRSA_BATCH=1 ./easyrsa build-client-full "$CLIENT_NAME" nopass
    
    # Create client config directory if it doesn't exist
    mkdir -p /etc/openvpn/clients
    
    # Get server's public IP
    SERVER_IP=$(curl -s ifconfig.me)
    
    # Generate client configuration
    cat > "/etc/openvpn/clients/$CLIENT_NAME.ovpn" << EOF
client
dev tun
proto udp
remote $SERVER_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3
EOF
    
    # Append certificates and keys
    echo "<ca>" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    cat "/etc/openvpn/ca.crt" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    echo "</ca>" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    
    echo "<cert>" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    cat "/etc/openvpn/easy-rsa/pki/issued/$CLIENT_NAME.crt" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    echo "</cert>" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    
    echo "<key>" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    cat "/etc/openvpn/easy-rsa/pki/private/$CLIENT_NAME.key" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    echo "</key>" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    
    echo "<tls-auth>" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    cat "/etc/openvpn/ta.key" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    echo "</tls-auth>" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    
    echo "key-direction 1" >> "/etc/openvpn/clients/$CLIENT_NAME.ovpn"
    
    echo "Client configuration generated at: /etc/openvpn/clients/$CLIENT_NAME.ovpn"
}

# Main execution
main() {
    # Check if running as root
    check_root
    
    # Install packages
    echo "Installing required packages..."
    install_packages
    
    # Set up PKI and CA
    echo "Setting up PKI and CA..."
    setup_pki
    
    # Set up server configuration
    echo "Setting up server configuration..."
    setup_server_config
    
    # Enable IP forwarding
    echo "Enabling IP forwarding..."
    enable_ip_forwarding
    
    # Configure firewall
    echo "Configuring firewall..."
    configure_firewall
    
    # Start OpenVPN service
    systemctl start openvpn@server
    systemctl enable openvpn@server
    
    # Generate client configuration
    echo "Generating client configuration..."
    read -p "Enter client name: " CLIENT_NAME
    generate_client_config "$CLIENT_NAME"
    
    echo "OpenVPN setup completed successfully!"
    echo "Client configuration file is available at: /etc/openvpn/clients/$CLIENT_NAME.ovpn"
}

# Run main function
main
