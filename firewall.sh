#!/bin/bash

### USECASES
# Block all traffic
#sudo ./firewall.sh --strict
#
# Enable secure default (Allow only requiered ports/protocols for package manager)
#sudo ./firewall.sh --secure
#
# Allow specific port and protocol
#sudo ./firewall.sh --allow <VALID-PORT> <tcp||udp>
### END USECASES

# Verify the script is running with sudo/root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run with sudo or as root."
  exit 1
fi

if ! command -v iptables &> /dev/null
  echo "ERROR: iptables is not installed."
  exit 1
fi

# Get the OS information from /etc/os-release
os_name=$(cat /etc/os-release | grep ^ID= | cut -d'=' -f2)

# Check if the OS is Ubuntu (1) or CentOS (0)
if [[ "$os_name" == "ubuntu" ]]; then
    os=1
elif [[ "$os_name" == "centos"]]; then
    os=0
else
    echo "ERROR: Unknown OS, THIS SCRIPT IS ONLY COMPATABLE WITH UBUNTU AND CENTOS"
    exit 1
fi

# Notify user of assumed OS
echo "OS of $os_name detected, running under that assumption"

case $1 in
  --strict)
    # Option 1: Block all traffic
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
    iptables -F
    iptables -X
    echo "All traffic blocked and rules flushed"
    ;;

  --secure)
    # Option 2: Default deny with package manager access
    iptables -F
    iptables -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    
    # Allow package manager dependencies
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT   # HTTP
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT   # DNS
    echo "Secure mode enabled with package manager access"
    ;;

  --allow)
    # Option 3: Allow specific port and protocol
    # Validate input parameters
    if [[ -z "$2" || -z "$3" ]]; then
        echo "Usage: $0 --allow <port> <tcp|udp>"
        exit 1
    fi

    # Port validation
    if ! [[ "$2" =~ ^[0-9]+$ ]] || (( "$2" < 1 || "$2" > 65535 )); then
        echo "ERROR: Invalid port number '$2' - must be 1-65535"
        exit 1
    fi

    # Protocol validation
    if [[ "$3" != "tcp" && "$3" != "udp" ]]; then
        echo "ERROR: Invalid protocol '$3' - must be 'tcp' or 'udp'"
        exit 1
    fi

    iptables -A INPUT -p $3 --dport $2 -j ACCEPT
    iptables -A OUTPUT -p $3 --sport $2 -j ACCEPT
    echo "Port $2/$3 allowed through firewall"
    ;;

  *)
    echo "Usage:"
    echo "  $0 --strict    #Block all network traffic"
    echo "  $0 --secure    #Default deny, but allow package manager's requiered port/protocols access"
    echo "  $0 --allow <VALID-PORT> <tcp||udp>  #Open specific port/protocol"
    exit 1
    ;;
esac

echo "Script has finished successfully"