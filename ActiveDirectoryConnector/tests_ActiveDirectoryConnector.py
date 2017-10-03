import unittest
from ActiveDirectoryConnector import *

class tests_ActiveDirectoryConnector(unittest.TestCase):
    def setUp(self):
        self.test_domain_dn = 'DC=hd,DC=local'
        self.test_domain_fqdn = 'hd.local'
        self.test_user_base_dn = 'CN=Users,%s' % self.test_domain_dn
        self.test_domain_admin_username = 'CN=Administrator,CN=Users,%s' % self.test_domain_dn
        self.test_domain_admin_password = 'Password1235!'

        # Add setup of test users in to here

    def get_ActiveDirectoryConnectorInstance(self):
        return ActiveDirectoryConnector(self.test_domain_dn,
                                        self.test_domain_fqdn,
                                        self.test_user_base_dn,
                                        self.test_domain_admin_username,
                                        self.test_domain_admin_password)

    def test__find_user_dn__whenCalledWithValidUser__returnsDNForUser(self):
        ads = self.get_ActiveDirectoryConnectorInstance()
        test_user = ads.find_user_dn('test_user_1')

        self.assertEqual('CN=test_user_1,%s' % self.test_user_base_dn, test_user)

    def test__find_user_dn__whenCalledWithUserThatReturnsMultipleEntries__raisesTooManyObjectsFoundException(self):
        ads = self.get_ActiveDirectoryConnectorInstance()

        with self.assertRaises(TooManyObjectsFoundException):
            ads.find_user_dn('*')

    def test__find_user_dn__whenCalledWithUserThatReturnsNoEntries__raisesCouldNotFindObjectException(self):
        ads = self.get_ActiveDirectoryConnectorInstance()

        with self.assertRaises(CouldNotFindObjectException):
            ads.find_user_dn('user_that_does_not_exist')

    def test__get_user_attributes__whenCalledWithValidUserAndAttributes__populatesDictionaryWithRelevantDetails(self):
        test_user_dn = 'CN=test_user_1,%s' % self.test_user_base_dn
        ads = self.get_ActiveDirectoryConnectorInstance()
        attributes = ads.get_user_attributes(test_user_dn, ['mobile', 'pager'])

        self.assertEqual('+447520634036', attributes['mobile'])
        self.assertEqual('123456789012', attributes['pager'])

    def test__get_user_attributes__whenCalledDNThatDoesNotExist__raisesCouldNotFindObjectException(self):
        test_user_dn = 'CN=user_that_does_not_exist,%s' % self.test_user_base_dn
        ads = self.get_ActiveDirectoryConnectorInstance()

        with self.assertRaises(CouldNotFindObjectException):
            ads.get_user_attributes(test_user_dn, ['mobile', 'pager'])

    def test__get_user_attributes__whenCalledDNThatDoesNotExist__raisesCouldNotFindObjectException(self):
        test_user_dn = 'CN=user_that_does_not_exist,%s' % self.test_user_base_dn
        ads = self.get_ActiveDirectoryConnectorInstance()

        with self.assertRaises(CouldNotFindObjectException):
            ads.get_user_attributes(test_user_dn, ['mobile', 'pager'])

    def test__bind__whenCalledWithValidUserDNAndPassword__returnsTrue(self):
        test_user_dn = 'CN=test_user_1,%s' % self.test_user_base_dn
        ads = self.get_ActiveDirectoryConnectorInstance()

        bound = ads.bind(test_user_dn, 'Password1')

        self.assertTrue(bound, 'User could not be bound')

    def test__bind__whenCalledWithValidUserDNAndIncorrectPassword__raisesIncorrectPasswordException(self):
        test_user_dn = 'CN=test_user_1,%s' % self.test_user_base_dn
        ads = self.get_ActiveDirectoryConnectorInstance()

        with self.assertRaises(IncorrectPasswordException):
            ads.bind(test_user_dn, 'Inc0rectP@s5sw0rd123!')



