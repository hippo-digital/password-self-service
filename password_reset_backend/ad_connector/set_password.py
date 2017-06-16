import pyad
from pyad import aduser


class set_password:
    def set(self, account_dn, password, domain_dn, server):
        user = pyad.aduser.ADUser.from_dn(account_dn, options={'ldap_server':server})
        user.set_password(password)

