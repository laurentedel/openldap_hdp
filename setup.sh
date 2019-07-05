#!/bin/bash

#
# Set script vars
#
SCRIPT_NAME=$(basename $0)
SCRIPT_DIR=`cd $(dirname $0) && pwd`

#
# Parse the args
#
LDAP_PASSWORD="$1"
LDAP_ADMIN_USER="$2"
LDAP_DOMAIN="$3"
LDAP_LDIF_DIR="$4"
LDAP_OU="$5"

echo -e "\n####  Installing OpenLDAP with the following args:
	password: $LDAP_PASSWORD
	admin user: $LDAP_ADMIN_USER
	ldap domain: $LDAP_DOMAIN
	ldif dir: $LDAP_LDIF_DIR
"

#
# Install EPEL repo
#
#echo -e "\n####  Installing the EPEL repo"
#cd /tmp && wget http://download.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm && rpm -ivh epel-release-6-8.noarch.rpm

yum install *openldap* openssl -y -q

#
# Start slapd on boot
#
echo -e "\n####  Enabling slapd to start on boot"
chkconfig --level 2345 slapd on


#
# Enabling logging
#
echo -e "\n####  Enabling OpenLDAP logging"
if [ ! -d "/var/log/slapd" ]; then
    mkdir /var/log/slapd
fi
chmod 755 /var/log/slapd/
chown ldap:ldap /var/log/slapd/
sed -i "/local4.*/d" /etc/rsyslog.conf

cat >> /etc/rsyslog.conf << EOF
local4.*                        /var/log/slapd/slapd.log
EOF
service rsyslog restart


#
# Convert to rfc2307bis schema
#
echo -e "\n####  Converting to the rfc2307bis schema to support posixGroup and groupOfNames"
SCHEMA_CONF_DIR=$SCRIPT_DIR/rfc2307bis

# Copy the schema and fix ownership
cp $SCHEMA_CONF_DIR/rfc2307bis.schema /etc/openldap/schema/
chown -R ldap:ldap /var/lib/ldap /etc/openldap

# Remove existing config database and database files
rm -rf /etc/openldap/slapd.d/*
rm -rf /var/lib/ldap/*

# Apply the nis stripped config
slapadd -F /etc/openldap/slapd.d/ -n 0 -l $SCHEMA_CONF_DIR/nis_remove.ldif

# Apply the rfc2307bis config
slapadd -F /etc/openldap/slapd.d/ -n 0 -l $SCHEMA_CONF_DIR/rfc2307bis.ldif


#
# Copy DB_CONFIG and fix ownership
#
echo -e "\n####  Copying DB_CONFIG and fixing ownership"
cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG
chown -R ldap:ldap /var/lib/ldap /etc/openldap


#
# Start slapd
#
echo -e "\n####  Starting slapd"
service slapd start


#
# Set the SSL certificate
#
echo -e "\n####  Creating the SSL certificate"
SSL_DIR=$SCRIPT_DIR/ssl
SSL_CONF_DIR=/etc/openldap/certs/
openssl genrsa -out $SSL_CONF_DIR/slapd.key 2048 
openssl req -new -x509 -key $SSL_CONF_DIR/slapd.key -out $SSL_CONF_DIR/slapd.crt -days 1095 < $SSL_DIR/input.txt


echo -e "\n####  Setting the certificate paths"
ldapmodify -Q -Y EXTERNAL -H ldapi:/// <<EOF
dn: cn=config
changetype:  modify
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/openldap/certs/slapd.crt
-
replace: olcTLSCACertificatePath
olcTLSCACertificatePath: /etc/openldap/certs
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/openldap/certs/slapd.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/openldap/certs/slapd.key
-
replace: olcTLSCipherSuite
olcTLSCipherSuite: HIGH:MEDIUM:+SSLv2

EOF

# enable LDAPS
echo -e "\n####  Enabling ldaps at start"
sed -i 's|^SLAPD_LDAPS.*|SLAPD_LDAPS=yes|g' /etc/sysconfig/ldap

# disable client cert validation
echo -e "\n####  Disabling client cert validation"
if ! grep -q TLS_REQCERT /etc/openldap/ldap.conf; then
    echo "TLS_REQCERT     allow" >> /etc/openldap/ldap.conf
fi


#
# Restart slapd
#
echo -e "\n####  Restarting slapd"
service slapd restart


#
# Set the domain suffix
#
echo -e "\n####  Setting the domain suffix"
ldapmodify -Q -Y EXTERNAL -H ldapi:/// <<EOF
dn: olcDatabase={2}bdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: $LDAP_DOMAIN

EOF

#
# Set the admin user
#
echo -e "\n####  Setting the admin user"
ldapmodify -Q -Y EXTERNAL -H ldapi:/// <<EOF
dn: olcDatabase={2}bdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=$LDAP_ADMIN_USER,$LDAP_DOMAIN

EOF

#
# Set the admin user password
#
echo -e "\n####  Setting the admin password"
ldapmodify -Q -Y EXTERNAL -H ldapi:/// <<EOF
dn: olcDatabase={2}bdb,cn=config
changetype: modify
replace: olcRootPW
olcRootPW: $LDAP_PASSWORD

EOF

#
# Set the config obj admin user
#
echo -e "\n####  Setting the config obj admin user"
ldapmodify -Q -Y EXTERNAL -H ldapi:/// <<EOF
dn: olcDatabase={0}config,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=$LDAP_ADMIN_USER,cn=config

EOF


#
# Set the config obj admin password
#
echo -e "\n####  Setting the config obj admin password"
ldapmodify -Q -Y EXTERNAL -H ldapi:/// <<EOF
dn: olcDatabase={0}config,cn=config
changetype: modify
replace: olcRootPW
olcRootPW: $LDAP_PASSWORD

EOF


#
# Stop slapd
#
echo -e "\n####  Stopping slapd"
service slapd stop


#
# Enable memberof and refint overlays
#
echo -e "\n####  Enabling memberof and refint overlays"
slapadd -v -n 0 -l $LDAP_LDIF_DIR/memberof_config.ldif
slapadd -v -n 0 -l $LDAP_LDIF_DIR/refint_config.ldif


#
# Fix ownership
#
echo -e "\n####  Fixing ownership"
chown -R ldap:ldap /var/lib/ldap /etc/openldap


#
# Start slapd
#
echo -e "\n####  Starting slapd"
service slapd start


#
# Setup ldif files
#
echo -e "\n####  Set domain in ldif files to $LDAP_DOMAIN"
sed -i "s/dc=hortonworks,dc=com/$LDAP_DOMAIN/g" $LDAP_LDIF_DIR/*.ldif
sed -i "s/ou: hortonworks.com/ou: $LDAP_OU/g" $LDAP_LDIF_DIR/*.ldif

#
# Add the base ou's
#
echo -e "\n####  Adding the base OU's"
ldapadd -D cn=$LDAP_ADMIN_USER,$LDAP_DOMAIN -w $LDAP_PASSWORD -f $LDAP_LDIF_DIR/base.ldif


#
# Add the admin user
#
echo -e "\n####  Adding the admin user"
ldapadd -D "cn=$LDAP_ADMIN_USER,$LDAP_DOMAIN" -h 127.0.0.1 -w $LDAP_PASSWORD <<EOF
dn: cn=$LDAP_ADMIN_USER,$LDAP_DOMAIN
objectclass:top
objectclass:person
objectclass:organizationalPerson
objectclass:inetOrgPerson
objectclass:posixaccount
cn: $LDAP_ADMIN_USER
sn: $LDAP_ADMIN_USER
uid: $LDAP_ADMIN_USER
homedirectory:/home/$LDAP_ADMIN_USER
uidNumber: 75000001
gidNumber: 75000001
userPassword: $LDAP_PASSWORD
description: Rootdn

EOF

#
# Add the users first
#
echo -e "\n####  Adding the users"
ldapadd -D cn=$LDAP_ADMIN_USER,$LDAP_DOMAIN -w $LDAP_PASSWORD -f $LDAP_LDIF_DIR/users.ldif

#
# Add the groups
#
echo -e "\n####  Adding the groups"
ldapadd -D cn=$LDAP_ADMIN_USER,$LDAP_DOMAIN -w $LDAP_PASSWORD -f $LDAP_LDIF_DIR/groups.ldif


#
# Configure Ambari
#

echo $LDAP_PASSWORD > /etc/ambari-server/conf/ldap-password.dat
echo "ambari.ldap.isConfigured=true
authentication.ldap.baseDn=$LDAP_DOMAIN
authentication.ldap.bindAnonymously=false
authentication.ldap.dnAttribute=$LDAP_DOMAIN
authentication.ldap.groupMembershipAttr=member
authentication.ldap.groupNamingAttr=cn
authentication.ldap.groupObjectClass=groupOfNames
authentication.ldap.managerDn=cn=$LDAP_ADMIN_USER,$LDAP_DOMAIN
authentication.ldap.managerPassword=/etc/ambari-server/conf/ldap-password.dat
authentication.ldap.primaryUrl=`hostname -f`:389
authentication.ldap.referral=ignore
authentication.ldap.useSSL=false
authentication.ldap.userObjectClass=inetOrgPerson
authentication.ldap.usernameAttribute=uid
client.security=ldap
ldap.sync.username.collision.behavior=convert" >> /etc/ambari-server/conf/ambari.properties

ambari-server start

echo "sleeping 30s for ambari server to come online"
sleep 30

#
# Synchronise all (users and groups) to Ambari
#
ambari-server sync-ldap --ldap-sync-admin-name=$LDAP_ADMIN_USER --ldap-sync-admin-password=$LDAP_PASSWORD --all


#
# Install NSLCD
#

yum install -y -q nss-pam-ldapd

sed -i.bak -e 's/^uri.*/uri ldap:\/\/`hostname -f`/' /etc/nslcd.conf
sed -i.bak -e 's/^base.*/base '$LDAP_DOMAIN'/' /etc/nslcd.conf
sed -i.bak -e 's/^#base   group/base   group ou=Groups,'$LDAP_DOMAIN'/' /etc/nslcd.conf
sed -i.bak -e 's/^#base   passwd/#base   passwd ou=Users,'$LDAP_DOMAIN'/' /etc/nslcd.conf
echo "#Mappings Ambari
filter passwd (objectClass=posixaccount) 
map passwd uidNumber uidNumber 
map passwd gidNumber gidNumber 
filter group (objectClass=posixgroup) 
uid nslcd 
gid ldap" >> /etc/nslcd.conf

sed -i.bak -e 's/^passwd.*/passwd: files ldap/' /etc/nsswitch.conf
sed -i.bak -e 's/^shadow.*/shadow: files/' /etc/nsswitch.conf
sed -i.bak -e 's/^group.*/group: files ldap/' /etc/nsswitch.conf

service nslcd start
chkconfig nslcd on

#
# Test NSLCD
#
id laurent

echo "must be: uid=75000010(laurent) gid=75000014(sales) groups=75000014(sales),75000013(finance)"

