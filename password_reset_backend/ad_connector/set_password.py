import logging

class set_password:
    def set(self, account_dn, domain_dn, server, password=None):
        self.log = logging.getLogger('password_reset_backend')

        import pyad
        user = pyad.aduser.ADUser.from_dn(account_dn, options={'ldap_server':server})

        if password is not None:
            user.set_password(password)

        try:
            user.update_attribute('lockoutTime', 0)
        except Exception as ex:
            self.log.exception('Method=set_password, Message=Unable to unlock user account, Account=%s' % account_dn)

