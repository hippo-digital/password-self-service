from ldap3 import Server, Connection, ALL

class ActiveDirectoryConnector:
    def __init__(self, domain_dn, domain_fqdn, user_base_dn, admin_user_dn, admin_user_password):
        self.domain_dn = domain_dn
        self.domain_fqdn = domain_fqdn
        self.user_base_dn = user_base_dn
        self.admin_user_dn = admin_user_dn
        self.admin_user_password = admin_user_password

    def find_user_dn(self, username):
        conn = self._search('(&(objectClass=user)(samAccountName=%s))' % username, {})
        return conn.entry_dn

    def get_user_attributes(self, user_dn, attribute_list):
        conn = self._search('(&(objectClass=user)(distinguishedName=%s))' % user_dn, attribute_list)
        ret = {}

        for key, value in conn.entry_attributes_as_dict.items():
            if len(value) > 0:
                ret[key] = value[0]

        return ret

    def bind(self, user_dn, password):
        conn = self._get_connection(user_dn=user_dn, password=password)

        return True

    def set_password(self, user_dn, new_password):
        return None

    def set_attributes(self, user_dn, attributes):
        return None

    def _search(self, search_term, attributes):
        conn = self._get_connection()
        conn.search(self.user_base_dn, search_term, attributes=attributes)

        if len(conn.entries) == 1:
            # entry_dn = conn.entries[0].entry_dn
            conn.unbind()
            return conn.entries[0]
        elif len(conn.entries) == 0:
            conn.unbind()
            raise CouldNotFindObjectException()
        else:
            conn.unbind()
            raise TooManyObjectsFoundException()

    def _get_connection(self, user_dn=None, password=None):
        server = Server(self.domain_fqdn, get_info=ALL, port=636, use_ssl=True)
        conn = Connection(server,
                          user=user_dn if user_dn != None else self.admin_user_dn,
                          password=password if user_dn != None else self.admin_user_password)

        try:
            conn.bind()
        except Exception as ex:
            raise CouldNotConnectToDirectoryException(ex)

        if conn.bound:
            return conn
        elif conn.last_error == 'invalidCredentials':
            raise IncorrectPasswordException()
        else:
            raise CouldNotConnectToDirectoryException()

class CouldNotConnectToDirectoryException(Exception):
    None

class CouldNotFindObjectException(Exception):
    None

class TooManyObjectsFoundException(Exception):
    None

class IncorrectPasswordException(Exception):
    None


