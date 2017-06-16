import pyad
from pyad import aduser, adquery


class search_object:
    def search(self, object_cn, domain_dn, server):
        query = pyad.adquery.ADQuery()

        query.execute_query(attributes = ["distinguishedName", "description"],
                                where_clause = "'cn' = '%s'" % object_cn,
                                base_dn = domain_dn)

        results = []

        for row in query.get_results():
            results.append(row['distinguishedName'])

        return results

