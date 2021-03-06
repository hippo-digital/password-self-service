from sys import platform

if platform == "win32":
    import pyad
    from pyad import *

    class search_object:
        def search(self, object_cn, domain_dn_list, fqdn):

            pyad.set_defaults(ldap_server=fqdn)

            query = adquery.ADQuery()
            results = []

            for domain_dn in domain_dn_list:
                try:
                    query.execute_query(attributes = ["distinguishedName", "description", "mobile", "pager"],
                                            where_clause = "'samAccountName' = '%s'" % object_cn,
                                            base_dn = domain_dn)

                    for row in query.get_results():
                        results.append(row)
                except:
                    pass

            return results

else:
    import ldap3

    class search_object:
        def search(self, object_cn, domain_dn_list, servername):
            server = ldap3.Server(servername)
            conn = ldap3.Connection(server, user='HD\\Administrator', password='Password123!')
            res = conn.bind()

            results = []

            for domain_dn in domain_dn_list:
                try:
                    conn.search(domain_dn, '(&(objectClass=person)(cn=%s))' % object_cn,
                                attributes=ldap3.ALL_ATTRIBUTES)

                    for row in conn.entries:
                        results.append(row)
                except:
                    pass

            return results

        def get_ldap_connection(server_details):
            server = ldap3.Server(server_details['server'])
            conn = ldap3.Connection(server, server_details['admin_dn'], password=server_details['admin_password'])
            conn.bind()

            return conn

        def get_ldap_object(ldap_conn, search_base_dn, search_spec):
            ldap_conn.search(search_base_dn, search_spec, attributes=ldap3.ALL_ATTRIBUTES)

            if len(ldap_conn.entries) == 1:
                return ldap_conn.entries[0]

