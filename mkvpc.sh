#!/bin/bash

motd () {
    echo " _    ______  ____________            __                                                  "
    echo "| |  / / __ \/ ____/_  __/___  ____  / /____             __  ___ __ __  _   __ ___   _____"
    echo "| | / / /_/ / /     / / / __ \/ __ \/ / ___/   _____    /  |/  // //_/ | | / // _ \ / ___/"
    echo "| |/ / ____/ /___  / / / /_/ / /_/ / (__  )   /____/   / /|_/ // ,<    | |/ // ___// /__  "
    echo "|___/_/    \____/ /_/  \____/\____/_/____/            /_/  /_//_/|_|   |___//_/    \___/  "
    echo "                                                                                          "
}

usage () {
    echo "Usage : $0"
    echo "        $0 [OPTION]"
    echo -e "\t-r, --vpc-range Plage IP du VPC"
    echo -e "\t--vpc-name Nom du VPC"
    echo -e "\t-p, --pub-subnet Plage IP du sous-réseau publique"
    echo -e "\t-q, --priv-subnet Plage IP du subnet privé"
    echo -e "\t-s, --ssh-ips Liste des IPs autorisé à utiliser SSH (séparé par des virgules)"
    echo -e "\t-h, --help Afficher l'aide et quitter"
    exit 0
}

gen_subnet_range () {
    local NET_PART=$(echo $1 | cut -d . -f 1,2)
    local HOST_PART=$(echo $1 | cut -d . -f 4 | cut -d / -f 1)
    #local RANG_PART=$(($(echo $1 | cut -d / -f 2) + 8))

    echo "$NET_PART.0.$HOST_PART/24:$NET_PART.1.$HOST_PART/24"
}

check_range () {
    if [[ ! "$1" =~ ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(0)(\/([4-9]|[12][0-9]|3[0-2]))$ ]]
    then
        echo "Plage IPv4 non valide - Exemple : 10.0.0.0/16"
        false
    else
        true
    fi
}

check_ipv4_list () {
    for ip in $(echo "$1" | sed "s/,/ /g")
    do
        if [[ ! "$ip" =~ ^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))$ ]]
        then
            echo "IPv4 non valide"
            false
            break
        fi
        true
    done
}

waiting_ec2_state () {
    echo -n "Démarrage de l'instance." | tee logs/main.log
    local state=$(aws ec2 describe-instances --instance-ids $1 --query Reservations[0].Instances[0].State.Name --output text)
    until [[ $state == "running" ]]
    do
        echo -n "."
        state=$(aws ec2 describe-instances --instance-ids $1 --query Reservations[0].Instances[0].State.Name --output text)
        sleep 1
    done
    echo ""
}

waiting_nat_state () {
    echo -n "Démarrage de la passerelle NAT." | tee logs/main.log
    nat_state=$(aws ec2 describe-nat-gateways --nat-gateway-ids $NAT_ID --query NatGateways[0].State --output text)
    until [[ $nat_state == "available" ]]
    do
        echo -n "."
        nat_state=$(aws ec2 describe-nat-gateways --nat-gateway-ids $NAT_ID --query NatGateways[0].State --output text)
        sleep 1
    done
    echo ""
}

clean_logs () {
    if [[ ! -d "logs" ]]
    then
        mkdir logs
    fi
    if [[ -f "logs/main.log" ]]
    then 
        cat logs/main.log >> logs/main.log.old
        rm logs/main.log 
    fi
    if [[ -f "logs/err.log" ]]
    then
        cat logs/err.log >> logs/err.log.old
        rm logs/err.log
    fi
    
}

create_pass () {
    cat /dev/urandom | tr -dc A-Za-z0-9 | head -c 30
}


interactive_mode () {
    clean_logs
    read -rp "Nom du VPC [ $VPC_NAME ] : " name
    if [[ ! -z $name ]]; then VPC_NAME=$name; fi

    read -rp "Plage IPv4 du VPC [ $VPC_RANGE ] : " range
    while ! check_range $VPC_RANGE
    do
        if [[ -z $range ]]; then break; fi
        read -rp "Plage IPv4 du VPC : " range
    done

    if [[ ! -z $range ]]; then VPC_RANGE=$range; fi
    
    local range=$(gen_subnet_range $VPC_RANGE)
    PUB_SUBNET_RANGE=$(echo $range | cut -d : -f 1)
    PRIV_SUBNET_RANGE=$(echo $range | cut -d : -f 2)

    read -rp "Plage IPv4 du sous-réseau publique [ $PUB_SUBNET_RANGE ] : " range
    while ! check_range $PUB_SUBNET_RANGE
    do
        if [[ -z $range ]]; then break; fi
        read -rp "Plage IPv4 du sous-réseau publique [ $PUB_SUBNET_RANGE ] : " range
    done

    if [[ ! -z $range ]]; then PUB_SUBNET_RANGE=$range; fi

    read -rp "Plage IPv4 du sous-réseau privé [ $PRIV_SUBNET_RANGE ] : " range
    while ! check_range $PRIV_SUBNET_RANGE
    do
        if [[ -z $range ]]; then break; fi
        read -rp "Plage IPv4 du sous-réseau privé [ $PRIV_SUBNET_RANGE ] : " range
    done

    if [ ! -z $range ]; then PRIV_SUBNET_RANGE=$range; fi

    read -rp "IPs qui pourront utiliser SSH (séparé par des virgules) [ $SSH_IPS ] : " ips
    while ! check_ipv4_list $SSH_IPS
    do
        if [[ -z $ips ]]; then break; fi
        read -rp "IPs autorisé à utiliser SSH (séparé par des virgules) [ $SSH_IPS ] : " ips
    done
    if [[ ! -z $ips ]]; then SSH_IPS=$ips; fi
    echo ""
}

passive_mode () {
    clean_logs
    OPTS=$(getopt --name $0 --options r:p:q:s:h --longoptions vpc-name:,vpc-range:,pub-subnet:,priv-subnet:,ssh-ips:,help -- "$@")
    if [[ $? -ne 0 ]]; then usage; fi
    eval set -- "$OPTS"

    while true
    do
        case $1 in
            --vpc-name)
                VPC_NAME=$2
                shift 2 ;;
            -r | --vpc-range)
                VPC_RANGE=$2
                if ! check_range $VPC_RANGE; then exit 1; fi
                shift 2 ;;
            -p | --pub-subnet)
                PUB_SUBNET_RANGE=$2
                if ! check_range $PUB_SUBNET_RANGE; then exit 1; fi
                shift 2 ;;
            -q | --priv-subnet)
                PRIV_SUBNET_RANGE=$2
                if ! check_range $PRIV_SUBNET_RANGE; then exit 1; fi
                shift 2 ;;
            -s | --ssh-ips)
                SSH_IPS=$2
                if ! check_ipv4_list $SSH_IPS; then exit 1; fi
                shift 2 ;;
            -h | --help)
                usage
                shift ;;
            --)
                shift
                break ;;
            *)
            usage ;;
        esac
    done

    if [[ ! -z PUB_SUBNET_RANGE && ! -z PRIV_SUBNET_RANGE ]]
    then
        local range=$(gen_subnet_range $VPC_RANGE)
        if [[ -z $PUB_SUBNET_RANGE ]]; then PUB_SUBNET_RANGE=$(echo $range | cut -d : -f 1); fi
        if [[ -z $PRIV_SUBNET_RANGE ]]; then PRIV_SUBNET_RANGE=$(echo $range | cut -d : -f 2); fi
    fi
}

VPC_NAME=my-vpc
VPC_RANGE=10.0.0.0/16
SSH_IPS=$(dig +short txt ch whoami.cloudflare @1.0.0.1 | tr -d '"')

motd

if [[ -z $1 ]]
then
    interactive_mode
else
    passive_mode $@
fi

PUB_SUBNET_NAME=$VPC_NAME-public-subnet
PRIV_SUBNET_NAME=$VPC_NAME-private-subnet
NAT_EIP_NAME=$VPC_NAME-nat-elastic-ip
IGW_NAME=$VPC_NAME-internet-gateway
NAT_NAME=$VPC_NAME-nat-gateway
PUB_RTB_NAME=$VPC_NAME-public-route-table
PRIV_RTB_NAME=$VPC_NAME-private-route-table
WEB_SG_NAME=$VPC_NAME-web-security-group
DB_SG_NAME=$VPC_NAME-db-security-group
IDS_SG_NAME=$VPC_NAME-ids-security-group
WEB_INSTANCE_NAME=$VPC_NAME-web-instance
WEB_EIP_NAME=$VPC_NAME-web-elastic-ip
DB_INSTANCE_NAME=$VPC_NAME-db-instance
DB_EIP_NAME=$VPC_NAME-db-elastic-ip
IDS_INSTANCE_NAME=$VPC_NAME-ids-instance
IDS_ENI_NAME=$VPC_NAME-ids-network-interface
TRAFFIC_MIRROR_TARGET_NAME=$VPC_NAME-traffic-mirror-target
TRAFFIC_MIRROR_FILTER_NAME=$VPC_NAME-traffic-mirror-filter
TRAFFIC_MIRROR_SESSION_NAME=$VPC_NAME-traffic-mirror-session
WEB_KEY_NAME=$VPC_NAME-web-key
DB_KEY_NAME=$VPC_NAME-db-key
IDS_KEY_NAME=$VPC_NAME-ids-key

echo "# $VPC_NAME" > $VPC_NAME.profile

set -e

echo "Création du VPC $VPC_RANGE.." | tee logs/main.log
VPC_ID=$(aws ec2 create-vpc --cidr-block $VPC_RANGE --tag-specifications ResourceType=vpc,Tags="[{Key=Name,Value=$VPC_NAME}]" --query Vpc.VpcId --output text)
echo "VPC_ID=$VPC_ID" >> $VPC_NAME.profile

echo "Création du sous-réseau $PUB_SUBNET_NAME.." | tee logs/main.log
PUB_SUBNET_ID=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block $PUB_SUBNET_RANGE --availability-zone us-east-1f --tag-specifications ResourceType=subnet,Tags="[{Key=Name,Value=$PUB_SUBNET_NAME}]" --query Subnet.SubnetId --output text)
PUB_SUBNET_AVAILABILITY_ZONE=$(aws ec2 describe-subnets --subnet-ids $PUB_SUBNET_ID --query "Subnets[0].AvailabilityZone" --output text)
echo "PUB_SUBNET_ID=$PUB_SUBNET_ID" >> $VPC_NAME.profile

echo "Création du sous-réseau $PRIV_SUBNET_NAME.." | tee logs/main.log
PRIV_SUBNET_ID=$(aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block $PRIV_SUBNET_RANGE --availability-zone us-east-1f --tag-specifications ResourceType=subnet,Tags="[{Key=Name,Value=$PRIV_SUBNET_NAME}]" --query Subnet.SubnetId --output text)
PRIV_SUBNET_AVAILABILITY_ZONE=$(aws ec2 describe-subnets --subnet-ids $PRIV_SUBNET_ID --query "Subnets[0].AvailabilityZone" --output text)
echo "PRIV_SUBNET_ID=$PRIV_SUBNET_ID" >> $VPC_NAME.profile

echo "Création de la passerelle Internet $IGW_NAME.." | tee logs/main.log
IGW_ID=$(aws ec2 create-internet-gateway --tag-specifications ResourceType=internet-gateway,Tags="[{Key=Name,Value=$IGW_NAME}]" --query InternetGateway.InternetGatewayId --output text)
aws ec2 attach-internet-gateway --vpc-id $VPC_ID --internet-gateway-id $IGW_ID
echo "IGW_ID=$IGW_ID" >> $VPC_NAME.profile

echo "Création de la passerelle NAT $NAT_NAME.." | tee logs/main.log
NAT_EIP_ID=$(aws ec2 allocate-address --tag-specifications ResourceType=elastic-ip,Tags="[{Key=Name,Value=$NAT_EIP_NAME}]" --query AllocationId --output text)
NAT_EIP_IP=$(aws ec2 describe-addresses --allocation-ids $NAT_EIP_ID --query Addresses[0].PublicIp --output text)
echo "NAT_EIP_ID=$NAT_EIP_ID" >> $VPC_NAME.profile
NAT_ID=$(aws ec2 create-nat-gateway --subnet-id $PUB_SUBNET_ID --allocation-id $NAT_EIP_ID --tag-specifications ResourceType=natgateway,Tags="[{Key=Name,Value=$NAT_NAME}]" --query NatGateway.NatGatewayId --output text)
waiting_nat_state
echo "NAT_ID=$NAT_ID" >> $VPC_NAME.profile


echo "Création de la tables de routage $PUB_RTB_NAME.." | tee logs/main.log
PUB_RTB_ID=$(aws ec2 create-route-table --vpc-id $VPC_ID --tag-specifications ResourceType=route-table,Tags="[{Key=Name,Value=$PUB_RTB_NAME}]" --query RouteTable.RouteTableId --output text)
echo "PUB_RTB_ID=$PUB_RTB_ID" >> $VPC_NAME.profile
aws ec2 create-route --route-table-id $PUB_RTB_ID --destination-cidr-block 0.0.0.0/0 --gateway-id $IGW_ID >> logs/main.log 2>> logs/err.log
PUB_RTB_ASSOC=$(aws ec2 associate-route-table  --subnet-id $PUB_SUBNET_ID --route-table-id $PUB_RTB_ID --query AssociationId --output text)
echo "PUB_RTB_ASSOC=$PUB_RTB_ASSOC" >> $VPC_NAME.profile

echo "Création de la tables de routage $PRIV_RTB_NAME.." | tee logs/main.log
PRIV_RTB_ID=$(aws ec2 create-route-table --vpc-id $VPC_ID --tag-specifications ResourceType=route-table,Tags="[{Key=Name,Value=$PRIV_RTB_NAME}]" --query RouteTable.RouteTableId --output text)
echo "PRIV_RTB_ID=$PRIV_RTB_ID" >> $VPC_NAME.profile
aws ec2 create-route --route-table-id $PRIV_RTB_ID --destination-cidr-block 0.0.0.0/0 --gateway-id $NAT_ID >> logs/main.log 2>> logs/err.log
PRIV_RTB_ASSOC=$(aws ec2 associate-route-table  --subnet-id $PRIV_SUBNET_ID --route-table-id $PRIV_RTB_ID --query AssociationId --output text)
echo "PRIV_RTB_ASSOC=$PRIV_RTB_ASSOC" >> $VPC_NAME.profile

echo "Création du groupe de sécurité $WEB_SG_NAME.." | tee logs/main.log
WEB_SG_ID=$(aws ec2 create-security-group --group-name $WEB_SG_NAME --description "Security group for Web servers" --vpc-id $VPC_ID --output text)
echo "WEB_SG_ID=$WEB_SG_ID" >> $VPC_NAME.profile
aws ec2 authorize-security-group-ingress --group-id $WEB_SG_ID --ip-permissions IpProtocol=icmp,FromPort='8',ToPort='-1',IpRanges=[{CidrIp=0.0.0.0/0}] >> logs/main.log 2>> logs/err.log
aws ec2 authorize-security-group-ingress --group-id $WEB_SG_ID --protocol tcp --port 80 --cidr 0.0.0.0/0 >> logs/main.log 2>> logs/err.log
aws ec2 authorize-security-group-ingress --group-id $WEB_SG_ID --protocol tcp --port 443 --cidr 0.0.0.0/0 >> logs/main.log 2>> logs/err.log
for ip in $(echo "$SSH_IPS" | sed "s/,/ /g")
do
    aws ec2 authorize-security-group-ingress --group-id $WEB_SG_ID --protocol tcp --port 22 --cidr $ip/32 >> logs/main.log 2>> logs/err.log
done


echo "Création du groupe de sécurité $DB_SG_NAME.." | tee logs/main.log
DB_SG_ID=$(aws ec2 create-security-group --group-name $DB_SG_NAME --description "Security group for DB Servers" --vpc-id $VPC_ID --output text)
echo "DB_SG_ID=$DB_SG_ID" >> $VPC_NAME.profile
aws ec2 authorize-security-group-ingress --group-id $DB_SG_ID --ip-permissions IpProtocol=icmp,FromPort='8',ToPort='-1',UserIdGroupPairs=[{GroupId=$WEB_SG_ID}] >> logs/main.log 2>> logs/err.log
aws ec2 authorize-security-group-ingress --group-id $DB_SG_ID --protocol tcp --port 3306 --source-group $WEB_SG_ID >> logs/main.log 2>> logs/err.log
aws ec2 authorize-security-group-ingress --group-id $DB_SG_ID --protocol tcp --port 22 --source-group $WEB_SG_ID >> logs/main.log 2>> logs/err.log


echo "Création du groupe de sécurité $IDS_SG_NAME.." | tee logs/main.log
IDS_SG_ID=$(aws ec2 create-security-group --group-name $IDS_SG_NAME --description "Security group for IDS Servers" --vpc-id $VPC_ID --output text)
echo "IDS_SG_ID=$IDS_SG_ID" >> $VPC_NAME.profile
aws ec2 authorize-security-group-ingress --group-id $IDS_SG_ID --ip-permissions IpProtocol=icmp,FromPort='8',ToPort='-1',IpRanges=[{CidrIp=$PUB_SUBNET_RANGE}] >> logs/main.log 2>> logs/err.log
aws ec2 authorize-security-group-ingress --group-id $IDS_SG_ID --protocol udp --port 4789 --cidr $PUB_SUBNET_RANGE >> logs/main.log 2>> logs/err.log
aws ec2 authorize-security-group-ingress --group-id $IDS_SG_ID --protocol tcp --port 22 --cidr $PUB_SUBNET_RANGE >> logs/main.log 2>> logs/err.log


echo "Création des clés privées pour la connexion aux instance.." | tee logs/main.log
if [[ -f "$PWD/$WEB_KEY_NAME.pem" || -f "$PWD/$DB_KEY_NAME.pem" ]]
then
    rm -f $PWD/$WEB_KEY_NAME.pem $PWD/$DB_KEY_NAME.pem
fi
aws ec2 create-key-pair --key-name $WEB_KEY_NAME --key-type ed25519 --query "KeyMaterial" --output text > $PWD/$WEB_KEY_NAME.pem
aws ec2 create-key-pair --key-name $DB_KEY_NAME --key-type ed25519 --query "KeyMaterial" --output text > $PWD/$DB_KEY_NAME.pem
aws ec2 create-key-pair --key-name $IDS_KEY_NAME --key-type ed25519 --query "KeyMaterial" --output text > $PWD/$IDS_KEY_NAME.pem
echo "WEB_KEY_NAME=$WEB_KEY_NAME" >> $VPC_NAME.profile
echo "DB_KEY_NAME=$DB_KEY_NAME" >> $VPC_NAME.profile
echo "IDS_KEY_NAME=$IDS_KEY_NAME" >> $VPC_NAME.profile

chmod 400 $PWD/$WEB_KEY_NAME.pem
chmod 400 $PWD/$DB_KEY_NAME.pem
chmod 400 $PWD/$IDS_KEY_NAME.pem

echo "Création de l'instance EC2 $DB_INSTANCE_NAME sous Debian 11 64 bit.." | tee logs/main.log

DB_PRIV_IP=$(echo $PRIV_SUBNET_RANGE | cut -d . -f 1-3 ).20
DB_ROOT_PASSWD=$(create_pass)
DB_USER_PASSWD=$(create_pass)

CONFIG_DB=$(cat << CONFIG
#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
sudo -E apt -y update
echo "update ok"
sudo -E apt -y upgrade
echo "upgrade ok"
sudo -E apt -y install mariadb-server
echo "mariadb ok"
sudo mariadb -u root << USER
UPDATE mysql.global_priv SET priv=json_set(priv, '$.plugin', 'mysql_native_password', '$.authentication_string', PASSWORD('$DB_ROOT_PASSWD')) WHERE User='root';
DELETE FROM mysql.global_priv WHERE User='';
DELETE FROM mysql.global_priv WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
CREATE DATABASE app;
USE app;
CREATE TABLE users(id int auto_increment, login varchar(255) not null, pass varchar(255) not null, primary key(id));
INSERT INTO users(login,pass) VALUES ('admin', 'admin'), ('toto', 'toto');
GRANT ALL PRIVILEGES ON app.* TO 'user'@'%' IDENTIFIED BY '$DB_USER_PASSWD' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EXIT;
USER
sudo sed -i 's/# port = 3306/port = 3306/' /etc/mysql/my.cnf
sudo sed -i 's/socket = \/run\/mysqld\/mysqld.sock/# socket = \/run\/mysqld\/mysqld.sock/' /etc/mysql/my.cnf
echo "[mysqld]" | sudo tee -a /etc/mysql/my.cnf
echo "skip-networking = 0" | sudo tee -a /etc/mysql/my.cnf
echo "skip-bind-address" | sudo tee -a /etc/mysql/my.cnf
sudo systemctl restart mariadb
CONFIG
)

DB_INSTANCE_ID=$(aws ec2 run-instances --image-id ami-09a41e26df464c548 --instance-type t3a.micro --placement AvailabilityZone=$PRIV_SUBNET_AVAILABILITY_ZONE --key-name $DB_KEY_NAME --security-group-ids $DB_SG_ID --subnet-id $PRIV_SUBNET_ID --private-ip-address $DB_PRIV_IP --tag-specifications ResourceType=instance,Tags="[{Key=Name,Value=$DB_INSTANCE_NAME}]" --query Instances[0].InstanceId --output text  --user-data "$CONFIG_DB")
waiting_ec2_state $DB_INSTANCE_ID
echo "DB_INSTANCE_ID=$DB_INSTANCE_ID" >> $VPC_NAME.profile

echo "Création de l'instance EC2 $WEB_INSTANCE_NAME sous Debian 11 64 bit.." | tee logs/main.log

WEB_PRIV_IP=$(echo $PUB_SUBNET_RANGE | cut -d . -f 1-3 ).10

cp template.php index.php
sed -i "s/dbhost/'$DB_PRIV_IP'/" index.php
sed -i "s/dbpass/'$DB_USER_PASSWD'/" index.php
PHP_FILE=$(cat index.php | base64)

CONFIG_WEB=$(cat << CONFIG
#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
sudo -E apt -y update
echo "update ok"
sudo -E apt -y upgrade
echo "upgrade ok"
sudo -E apt -y install nginx php-fpm php-mysqli
echo "nginx ok"
echo "$PWD"
sudo sed -i 's/index index.html index.htm index.nginx-debian.html;/index index.html index.htm index.nginx-debian.html index.php;/' /etc/nginx/sites-available/default

sudo sed -i '56,63s/#//' /etc/nginx/sites-available/default
sudo sed -i '62s/fast/#fast/' /etc/nginx/sites-available/default

echo "modif default ok"
echo '$PHP_FILE' | base64 -d > /tmp/index.php && echo "envoie ok"
sudo cp /tmp/index.php /var/www/html/index.php && echo "copie ok"
sudo rm /var/www/html/index.nginx-debian.html
sudo chown -R www-data:www-data /var/www/html/ && echo "chown ok"
sudo systemctl restart nginx && echo "restart ok"
CONFIG
)

WEB_INSTANCE_ID=$(aws ec2 run-instances --image-id ami-09a41e26df464c548 --instance-type t3a.micro --placement AvailabilityZone=$PUB_SUBNET_AVAILABILITY_ZONE --key-name $WEB_KEY_NAME --security-group-ids $WEB_SG_ID --private-ip-address $WEB_PRIV_IP --subnet-id $PUB_SUBNET_ID --tag-specifications ResourceType=instance,Tags="[{Key=Name,Value=$WEB_INSTANCE_NAME}]" --query Instances[0].InstanceId --output text --user-data "$CONFIG_WEB")
waiting_ec2_state $WEB_INSTANCE_ID
WEB_EIP_ID=$(aws ec2 allocate-address --tag-specifications ResourceType=elastic-ip,Tags="[{Key=Name,Value=$WEB_EIP_NAME}]" --query AllocationId --output text)
WEB_EIP_IP=$(aws ec2 describe-addresses --allocation-ids $WEB_EIP_ID --query Addresses[0].PublicIp --output text)
WEB_ENI_ID=$(aws ec2 describe-instances --instance-ids $WEB_INSTANCE_ID --query Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId --output text)
aws ec2 associate-address --instance-id $WEB_INSTANCE_ID --allocation-id $WEB_EIP_ID >> logs/main.log 2>> logs/err.log
echo "WEB_EIP_ID=$WEB_EIP_ID" >> $VPC_NAME.profile
echo "WEB_INSTANCE_ID=$WEB_INSTANCE_ID" >> $VPC_NAME.profile
rm index.php

echo "Création de l'instance EC2 $IDS_INSTANCE_NAME sous Debian 11 64 bit.." | tee logs/main.log

IDS_PRIV_IP=$(echo $PRIV_SUBNET_RANGE | cut -d . -f 1-3 ).30

CONFIG_IDS=$(cat << CONFIG
#!/bin/bash
export DEBIAN_FRONTEND=noninteractive
sudo -E apt -y update
sudo -E apt -y upgrade
sudo -E apt -y install snort
cat <<EOT >> /etc/snort/rules/local.rules
alert udp any any -> any any (msg: "Error Based SQL Injection Detected"; content: "%27" ; sid:100000011; )
alert udp any any -> any any (msg: "Error Based SQL Injection Detected"; content: "22" ; sid:100000012; )
alert udp any any -> any any (msg: "AND SQL Injection Detected"; content: "and" ; nocase; sid:100000060; )
alert udp any any -> any any (msg: "OR SQL Injection Detected"; content: "or" ; nocase; sid:100000061; )    
EOT
sudo sed -i 's/192.168.0.0\/16/$(echo $VPC_RANGE | cut -d / -f 1)\/$(echo $VPC_RANGE | cut -d / -f 2)/' /etc/snort/snort.debian.conf
sudo sed -i 's/ipvar HOME_NET any/ipvar HOME_NET $(echo $VPC_RANGE | cut -d / -f 1)/' /etc/snort/snort.conf
sudo systemctl enable snort
sudo systemctl restart snort
CONFIG
)

IDS_INSTANCE_ID=$(aws ec2 run-instances --image-id ami-09a41e26df464c548 --instance-type t3a.micro --private-ip-address $IDS_PRIV_IP --placement AvailabilityZone=$PRIV_SUBNET_AVAILABILITY_ZONE --key-name $IDS_KEY_NAME --security-group-ids $IDS_SG_ID --subnet-id $PRIV_SUBNET_ID --tag-specifications ResourceType=instance,Tags="[{Key=Name,Value=$IDS_INSTANCE_NAME}]" --query Instances[0].InstanceId --output text --user-data "$CONFIG_IDS")
waiting_ec2_state $IDS_INSTANCE_ID
IDS_ENI_ID=$(aws ec2 describe-instances --instance-ids $IDS_INSTANCE_ID --query Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId --output text)
echo "IDS_INSTANCE_ID=$IDS_INSTANCE_ID" >> $VPC_NAME.profile

echo "Mise en place du traffic mirroring.." | tee logs/main.log

TRAFFIC_MIRROR_TARGET_ID=$(aws ec2 create-traffic-mirror-target --network-interface-id $IDS_ENI_ID  --description "IDS appliance as traffic mirroring target" --query TrafficMirrorTarget.TrafficMirrorTargetId --output text)
TRAFFIC_MIRROR_FILTER_ID=$(aws ec2 create-traffic-mirror-filter --description "traffic mirroring filter for IDS appliance" --query TrafficMirrorFilter.TrafficMirrorFilterId --output text)
aws ec2 create-traffic-mirror-filter-rule --traffic-mirror-filter-id $TRAFFIC_MIRROR_FILTER_ID --traffic-direction ingress --rule-number 1 --rule-action accept --destination-cidr-block 0.0.0.0/0 --source-cidr-block 0.0.0.0/0 >> logs/main.log 2>> logs/err.log
TRAFFIC_MIRROR_SESSION_ID=$(aws ec2 create-traffic-mirror-session --traffic-mirror-target-id $TRAFFIC_MIRROR_TARGET_ID --network-interface-id $WEB_ENI_ID --session-number 1 --traffic-mirror-filter-id $TRAFFIC_MIRROR_FILTER_ID --description "traffic mirroring session for IDS appliance" --query TrafficMirrorSession.TrafficMirrorSessionId --output text)
echo "TRAFFIC_MIRROR_TARGET_ID=$TRAFFIC_MIRROR_TARGET_ID" >> $VPC_NAME.profile
echo "TRAFFIC_MIRROR_FILTER_ID=$TRAFFIC_MIRROR_FILTER_ID" >> $VPC_NAME.profile
echo "TRAFFIC_MIRROR_SESSION_ID=$TRAFFIC_MIRROR_SESSION_ID" >> $VPC_NAME.profile

echo "Montage des tunnels SSH.."

ssh -f -o StrictHostKeyChecking=no -i $WEB_KEY_NAME.pem admin@$WEB_EIP_IP -L 2200:$DB_PRIV_IP:22 -N >> logs/main.log 2>> logs/err.log
ssh -f -o StrictHostKeyChecking=no -i $WEB_KEY_NAME.pem admin@$WEB_EIP_IP -L 2201:$IDS_PRIV_IP:22 -N >> logs/main.log 2>> logs/err.log

echo -e "\nRécapitulatif du VPC créé"
echo "=========================="
echo "$VPC_NAME"
echo -e "\tID : $VPC_ID"
echo -e "\tPlage : $VPC_RANGE"
echo "---------------------------------------------------------------------------------"
echo -e "\t$PUB_SUBNET_NAME :"
echo -e "\t\tID : $PUB_SUBNET_ID"
echo -e "\t\tPlage : $PUB_SUBNET_RANGE"
echo -e "\t\tPasserelle Internet: $IGW_NAME"
echo -e "\t\t\tID : $IGW_ID"
echo -e "\t\tTable de routage : $PUB_RTB_NAME"
echo -e "\t\t\tID : $PUB_RTB_ID"
echo -e "\t\tGroupe de sécurité : $WEB_SG_NAME"
echo -e "\t\t\tID : $WEB_SG_ID"
echo -e "\t\tInstance : $WEB_INSTANCE_NAME"
echo -e "\t\t\tID : $WEB_INSTANCE_ID"
echo -e "\t\t\tIP Elastic : $WEB_EIP_IP"
echo -e "\t\t\t\tID : $WEB_EIP_ID"
echo -e "\t\t\tClé privé SSH : $PWD/$WEB_KEY_NAME.pem"
echo "---------------------------------------------------------------------------------"
echo -e "\t$PRIV_SUBNET_NAME :"
echo -e "\t\tID : $PRIV_SUBNET_ID"
echo -e "\t\tPlage : $PRIV_SUBNET_RANGE"
echo -e "\t\tPasserelle NAT: $NAT_NAME"
echo -e "\t\t\tID : $NAT_ID"
echo -e "\t\t\tIP Elastic : $NAT_EIP_IP"
echo -e "\t\t\t\tID : $NAT_EIP_ID"
echo -e "\t\tTable de routage : $PRIV_RTB_NAME"
echo -e "\t\t\tID : $PRIV_RTB_ID"
echo -e "\t\tGroupe de sécurité : $DB_SG_NAME"
echo -e "\t\t\tID : $DB_SG_ID"
echo -e "\t\tInstance : $DB_INSTANCE_NAME"
echo -e "\t\t\tID : $DB_INSTANCE_ID"
echo -e "\t\t\tIP privée : $DB_PRIV_IP"
echo -e "\t\t\tClé privé SSH : $PWD/$DB_KEY_NAME.pem"
echo -e "\t\t\tMot de passe MariaDB root : $DB_ROOT_PASSWD"
echo -e "\t\t\tMot de passe MariaDB user : $DB_USER_PASSWD"
echo -e "\t\tGroupe de sécurité : $IDS_SG_NAME"
echo -e "\t\t\tID : $IDS_SG_ID"
echo -e "\t\tInstance : $IDS_INSTANCE_NAME"
echo -e "\t\t\tID : $IDS_INSTANCE_ID"
echo -e "\t\t\tIP privée : $IDS_PRIV_IP"
echo -e "\t\t\tClé privé SSH : $PWD/$IDS_KEY_NAME.pem"
echo -e "\t\tMise en mirroir du traffic :"
echo -e "\t\t\tCible : $TRAFFIC_MIRROR_TARGET_ID"
echo -e "\t\t\tFiltre : $TRAFFIC_MIRROR_FILTER_ID"
echo -e "\t\t\tFiltre : $TRAFFIC_MIRROR_FILTER_ID"
echo -e "\t\t\tSession : $TRAFFIC_MIRROR_SESSION_ID"
echo -e "\t\tTunnels SSH :"
echo -e "\t\t\t$DB_INSTANCE_NAME : ssh -i $DB_KEY_NAME.pem -p 2200 admin@localhost"
echo -e "\t\t\t$IDS_INSTANCE_NAME : ssh -i $IDS_KEY_NAME.pem -p 2201 admin@localhost"
