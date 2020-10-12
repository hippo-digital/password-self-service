FROM osixia/openldap

ENV LDAP_ORGANISATION="Test Org" \
    LDAP_DOMAIN="hd.local"

COPY user.schema /container/service/slapd/assets/config/bootstrap/schema/user.schema

COPY security.ldif /container/service/slapd/assets/config/bootstrap/ldif/02-security.ldif
COPY bootstrap.ldif /container/service/slapd/assets/config/bootstrap/ldif/50-bootstrap.ldif
COPY bootstrap2.ldif /container/service/slapd/assets/config/bootstrap/ldif/51-bootstrap.ldif
COPY hosts /etc/hosts
