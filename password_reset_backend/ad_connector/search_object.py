# import pyad
# from pyad import aduser, adquery

class search_object:
    def search(self, object_cn, domain_dn_list):
        import pyad
        from pyad import aduser, adquery

        query = pyad.adquery.ADQuery()
        results = []

        for domain_dn in domain_dn_list:
            query.execute_query(attributes = ["distinguishedName", "description", "mobile", "pager"],
                                    where_clause = "'samAccountName' = '%s'" % object_cn,
                                    base_dn = domain_dn)

            for row in query.get_results():
                results.append(row)

        return results

# import ldap3

# class search_object:
#     def search(self, object_cn, domain_dn, servername):
#         server = ldap3.Server(servername)
#         conn = ldap3.Connection(server, user='HD\\Administrator', password='Password123!')
#         conn.bind()
#
#         conn.search(domain_dn, '(&(objectClass=person)(cn=%s))' % object_cn, attributes=ldap3.ALL_ATTRIBUTES)
#
#         if len(conn.entries) == 1:
#             return conn.entries[0]
#
#     def get_ldap_connection(server_details):
#         server = ldap3.Server(server_details['server'])
#         conn = ldap3.Connection(server, server_details['admin_dn'], password=server_details['admin_password'])
#         conn.bind()
#
#         return conn
#
#     def get_ldap_object(ldap_conn, search_base_dn, search_spec):
#         ldap_conn.search(search_base_dn, search_spec, attributes=ldap3.ALL_ATTRIBUTES)
#
#         if len(ldap_conn.entries) == 1:
#             return ldap_conn.entries[0]

