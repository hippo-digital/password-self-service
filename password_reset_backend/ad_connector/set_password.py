import logging

class set_password:
    def set(self, account_dn, password, domain_dn, server):
        self.log = logging.getLogger('password_reset_backend')

        import pyad
        user = pyad.aduser.ADUser.from_dn(account_dn, options={'ldap_server':server})
        user.set_password(password)

        try:
            user.update_attribute('lockoutTime', 0)
        except Exception as ex:
            self.log.exception('Method=set_password, Message=Unable to unlock user account, Account=%s' % account_dn)

