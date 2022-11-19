#!/bin/bash

motd () {
    echo " _    ______  ____________            __                                                  "
    echo "| |  / / __ \/ ____/_  __/___  ____  / /____             ___   __  ___  _   __ ___   _____"
    echo "| | / / /_/ / /     / / / __ \/ __ \/ / ___/   _____    / _ \ /  |/  / | | / // _ \ / ___/"
    echo "| |/ / ____/ /___  / / / /_/ / /_/ / (__  )   /____/   / , _// /|_/ /  | |/ // ___// /__  "
    echo "|___/_/    \____/ /_/  \____/\____/_/____/            /_/|_|/_/  /_/   |___//_/    \___/  "
    echo "                                                                                          "
}

usage () {
    echo "Usage : $0 [OPTION]"
    echo -e "\t-p, --profile Plage IP du VPC"
    echo -e "\t-h, --help Afficher l'aide et quitter"
    exit 0
}

valid () {
    if [[ $? -ne 0 ]]; then exit 1; fi
}

parse_args () {
    OPTS=$(getopt --name $0 --options p:h --longoptions profile:,help -- "$@")
    if [[ $? -ne 0 ]]; then usage; fi
    eval set -- "$OPTS"

    while true
    do
        case $1 in
            -p | --profile)
                PROFILE=$2
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
}

motd

if [[ -z $1 ]]
then
    usage
fi

parse_args $@

if [[ ! -f $PROFILE ]]
then
    echo "Profile $PROFILE inexistant"
    exit 1
else
    source $PROFILE
fi

echo "Suppression du traffic mirroring..."
aws ec2 delete-traffic-mirror-session --traffic-mirror-session-id $TRAFFIC_MIRROR_SESSION_ID > /dev/null 2>&1
aws ec2 delete-traffic-mirror-filter --traffic-mirror-filter-id $TRAFFIC_MIRROR_FILTER_ID > /dev/null 2>&1
aws ec2 delete-traffic-mirror-target --traffic-mirror-target-id $TRAFFIC_MIRROR_TARGET_ID > /dev/null 2>&1

echo -n "Suppression des instances $WEB_INSTANCE_ID, $DB_INSTANCE_ID et $IDS_INSTANCE_ID."
aws ec2 terminate-instances --instance-ids $WEB_INSTANCE_ID $DB_INSTANCE_ID $IDS_INSTANCE_ID > /dev/null 2>&1

web_state=$(aws ec2 describe-instances --instance-ids $WEB_INSTANCE_ID --query Reservations[0].Instances[0].State.Name --output text)
db_state=$(aws ec2 describe-instances --instance-ids $DB_INSTANCE_ID --query Reservations[0].Instances[0].State.Name --output text)
ids_state=$(aws ec2 describe-instances --instance-ids $IDS_INSTANCE_ID --query Reservations[0].Instances[0].State.Name --output text)
until [[ $web_state == "terminated" && $db_state == "terminated" && $ids_state == "terminated" ]]
do
    echo -n "."
    web_state=$(aws ec2 describe-instances --instance-ids $WEB_INSTANCE_ID --query Reservations[0].Instances[0].State.Name --output text)
    db_state=$(aws ec2 describe-instances --instance-ids $DB_INSTANCE_ID --query Reservations[0].Instances[0].State.Name --output text)
    ids_state=$(aws ec2 describe-instances --instance-ids $IDS_INSTANCE_ID --query Reservations[0].Instances[0].State.Name --output text)
    sleep 1
done
echo ""

echo "Suppression des clés privées SSH $WEB_KEY_NAME, $DB_KEY_NAME et $IDS_KEY_NAME.."
aws ec2 delete-key-pair --key-name $WEB_KEY_NAME > /dev/null 2>&1
aws ec2 delete-key-pair --key-name $DB_KEY_NAME > /dev/null 2>&1
aws ec2 delete-key-pair --key-name $IDS_KEY_NAME > /dev/null 2>&1


echo "Suppression des groupes de sécurité $WEB_SG_ID, $DB_SG_ID et $IDS_SG_ID.."
aws ec2 delete-security-group --group-id $DB_SG_ID > /dev/null 2>&1
aws ec2 delete-security-group --group-id $WEB_SG_ID > /dev/null 2>&1
aws ec2 delete-security-group --group-id $IDS_SG_ID > /dev/null 2>&1

echo "Suppressions des tables de routage $PUB_RTB_ID et $PRIV_RTB_ID.."
aws ec2 disassociate-route-table --association-id $PUB_RTB_ASSOC > /dev/null 2>&1
aws ec2 disassociate-route-table --association-id $PRIV_RTB_ASSOC > /dev/null 2>&1
aws ec2 delete-route-table --route-table-id $PRIV_RTB_ID > /dev/null 2>&1
aws ec2 delete-route-table --route-table-id $PUB_RTB_ID > /dev/null 2>&1

echo -n "Suppression de la passerelle NAT $NAT_ID."
aws ec2 delete-nat-gateway --nat-gateway-id $NAT_ID > /dev/null 2>&1

nat_state=$(aws ec2 describe-nat-gateways --nat-gateway-ids $NAT_ID --query NatGateways[0].State --output text)
until [[ $nat_state == "deleted" ]]
do
    echo -n "."
    nat_state=$(aws ec2 describe-nat-gateways --nat-gateway-ids $NAT_ID --query NatGateways[0].State --output text)
    sleep 1
done
echo ""

echo "Suppression des adresses IP Elastic $WEB_EIP_ID et $NAT_EIP_ID.."
aws ec2 release-address --allocation-id $WEB_EIP_ID > /dev/null 2>&1
aws ec2 release-address --allocation-id $NAT_EIP_ID > /dev/null 2>&1

echo "Supressions des sous-réseaux $PUB_SUBNET_ID et $PRIV_SUBNET_ID.."
aws ec2 delete-subnet --subnet-id $PUB_SUBNET_ID > /dev/null 2>&1
aws ec2 delete-subnet --subnet-id $PRIV_SUBNET_ID > /dev/null 2>&1

echo -n "Suppression de la passerelle Internet $IGW_ID."
aws ec2 detach-internet-gateway --internet-gateway-id $IGW_ID --vpc-id $VPC_ID > /dev/null 2>&1

igw_state=$(aws ec2 describe-internet-gateways --internet-gateway-ids $IGW_ID --query InternetGateways[0].Attachments[0].State --output text)
until [[ $igw_state == "None" ]]
do
    echo -n "."
    nat_state=$(aws ec2 describe-internet-gateways --internet-gateway-ids $IGW_ID --query InternetGateways[0].Attachments[0].State --output text)
    sleep 1
done
echo ""

aws ec2 delete-internet-gateway --internet-gateway-id $IGW_ID > /dev/null 2>&1

echo "Supression du VPC $VPC_ID.."
aws ec2 delete-vpc --vpc-id $VPC_ID > /dev/null 2>&1

echo "Suppression des fichiers liés au VPC.."
rm -f $WEB_KEY_NAME.pem $DB_KEY_NAME.pem $IDS_KEY_NAME.pem $PROFILE
