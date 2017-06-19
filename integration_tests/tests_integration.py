import unittest

class load_users(unittest.TestCase):
    def setUp(self):
        self.src_ldap_server = {'server': '10.211.55.20',
                                'admin_dn': 'uid=Administrator,cn=users,dc=hd,dc=local',
