import unittest
import json
from Crypto.PublicKey import RSA
from Crypto import Random
import base64
import mock
import poller


class tests_poller(unittest.TestCase):
    # This method will be used by the mock to replace requests.get
    def mocked_send_sms(self, *args, **kwargs):
        class SendSMSSuccess:
            class messages():
                def create(self, to=None, from_=None, body=None):
                    None

        return SendSMSSuccess()

    def mocked_requests_get_code(self, *args, **kwargs):
        class MockedRequestsGet:
            def __init__(self):
                self.status_code = 200
                self.content = '["MEBhBARHkGhtV0Uuqx-2XodfjO4gGkD1DMlk-vg_gy-D5tlT-097uFW5g8GpHax9bpcSq0YrBAgEKrPu5fHVeUooWFoyC3lSzGYpbO8ErqZxYXaD0gk4ruxtLG4URuTOkO6ncji7znCqRhJzuPogZM8ywQtHnG9HS4sylU_KaHr_-Oyng09_YPu4XsHo9tbiohA2SSD_SMzEssOPR83Rw0hqADBMpBncj-1Zc6khowp6DaQtqGaBDoWjQR3SLLt5pjJZ7oucs2-augH745KjV-Nj6ZG8t0i7au6mVBZ0zWcb0IeWIc9YfuPh3zckmQYiZgvoYRaeqttOvW8iodbg9g==.DGTum8yZyviQBBSNQzP5Yy4SM8H8X7VNsiCBFlAB2HNhX_q_whboArJIhMMSG-lDCWyvpz9nuw63w7oHd9i8DVieGOshod-n5qkSxXjfoccS2r-58Srd4wsEV7CpYnJ_dKhTD_vbPlo5qm6J1BvQMg=="]'.encode('utf-8')

        return MockedRequestsGet()

    def mocked_requests_get_reset(self, *args, **kwargs):
        class MockedRequestsGet:
            def __init__(self):
                self.status_code = 200
                self.content = '["i4Mcz3MbIhy37n7A44UjQLAbhwyl6MA8KrrdTF_7oy4S8YcU7QIa6V7EwCkE0mOtwU1kl45Ic1D6IZNb-IUXgy02oLZ8MVfmwSSX2Z-s4qFr3hg3_Me_fCWJ3mbWKusRoW5lm00i3AbIDXefcRpUrfxcL_pPS7nqg-xMJ9VIiyVxFlzOH1K5s4H3PtCLplhWZWIHRyMUit10UiYkP20exR92eO-HFbDkPOtW84gxKkRmDxsfTIZERgdspmCSyaIBYx0qMdnVigTN_Hs2vE2fCdpp9CEzuYDgbbdHhlFjhAuS1Hc9Fif8C3M_MmLYbP0c5w4hmEWx_t0_zog9uTy9Hg==.BYQU1lyWhNGqE01UybF5jSPcEfq-pzdwCDp6bilfEBM7WPV2et4PL8TR0Hmyxt7xZplagFuOoXPaeF6mQh-V30HdxHncf9dN3k63yHkHGOfBJREO-K9-QOFy_rIB_Dchv8ZTc_YliiLLtn41wIZxLNf6V6YijX8B4oVHiNlQrS5XeLW-8u0_6T7kGv9r2eiNjROc2pGWyQxshfCMOhvSwfKMx1jkQxc9O7TXFP1TjBNr9Dt4v94YImpa-udbd9hoz78f4DkXOBnUfqR6qydi7d_N8Hb23sKIO-6SttWZUxNqlc1FoSbKdiSOKZvZY2ARhCDuDGAbnrEKbFIgS24j03UEltpYcAZveEQByxCQoiDmZQev60elOCIijwxvym-qznd63q3NF_97NjbVFPbeDMen17dkIvZ2i3hfkqr0mPaQpw4CetawrWOYwC7dvfsZb-l0xHD2x8blxkW4hFce1UVdsOH5Jsd8dF_-9vFwUidbyc-LhgLXphj3XC2jwPoBeqIitGqYbNJYwtfE6iYByNre9w7tb8oFQYWf1kqU5c-cpewzTKpPSWzjNjRw0cvk-OSmG_T_CVg3kBR5mYt8oywDhhUR4PGZdx8MgAY8fDw9m5ARFoA3uFMArOCsTDEOb8LkAWM_ucWuT3J4GoHtSBE90k7949tnGU-ypcWkSbG1ZcvcaxTR1NBwl4GF4AisR8rpBrshV_R6JX5nwKMD1itsIUTbzCWnEGfUb3ULrcpV99T17hTIb0-MFoNDqYlNyBcnHDhS_u17j_N25W5zp_NLpF3u2KJqDjQvb6euxI0OPVzQGGAAB6f8_YGAQa1Cg2eoXae0iY6cw5ZoFPomz9BPv1Lei0m3S7vsfw5ERyZhX459gaLF2y8oqsFjbjbi9txDeC4uQ-NMoPvfO0ZEOw=="]'.encode('utf-8')

        return MockedRequestsGet()

    def mocked_pyad(self, *args, **kwargs):
        class MockedPyAD:
            def __init__(self):
                self.results = []

            def get_results(self):
                return self.results

            def execute_query(self, attributes=None, where_clause=None, base_dn=None):
                return None

        return MockedPyAD()

    def setUp(self):
        self.test_code_request_raw = 'MEBhBARHkGhtV0Uuqx-2XodfjO4gGkD1DMlk-vg_gy-D5tlT-097uFW5g8GpHax9bpcSq0YrBAgEKrPu5fHVeUooWFoyC3lSzGYpbO8ErqZxYXaD0gk4ruxtLG4URuTOkO6ncji7znCqRhJzuPogZM8ywQtHnG9HS4sylU_KaHr_-Oyng09_YPu4XsHo9tbiohA2SSD_SMzEssOPR83Rw0hqADBMpBncj-1Zc6khowp6DaQtqGaBDoWjQR3SLLt5pjJZ7oucs2-augH745KjV-Nj6ZG8t0i7au6mVBZ0zWcb0IeWIc9YfuPh3zckmQYiZgvoYRaeqttOvW8iodbg9g==.DGTum8yZyviQBBSNQzP5Yy4SM8H8X7VNsiCBFlAB2HNhX_q_whboArJIhMMSG-lDCWyvpz9nuw63w7oHd9i8DVieGOshod-n5qkSxXjfoccS2r-58Srd4wsEV7CpYnJ_dKhTD_vbPlo5qm6J1BvQMg=='
        self.test_reset_request_raw = 'i4Mcz3MbIhy37n7A44UjQLAbhwyl6MA8KrrdTF_7oy4S8YcU7QIa6V7EwCkE0mOtwU1kl45Ic1D6IZNb-IUXgy02oLZ8MVfmwSSX2Z-s4qFr3hg3_Me_fCWJ3mbWKusRoW5lm00i3AbIDXefcRpUrfxcL_pPS7nqg-xMJ9VIiyVxFlzOH1K5s4H3PtCLplhWZWIHRyMUit10UiYkP20exR92eO-HFbDkPOtW84gxKkRmDxsfTIZERgdspmCSyaIBYx0qMdnVigTN_Hs2vE2fCdpp9CEzuYDgbbdHhlFjhAuS1Hc9Fif8C3M_MmLYbP0c5w4hmEWx_t0_zog9uTy9Hg==.BYQU1lyWhNGqE01UybF5jSPcEfq-pzdwCDp6bilfEBM7WPV2et4PL8TR0Hmyxt7xZplagFuOoXPaeF6mQh-V30HdxHncf9dN3k63yHkHGOfBJREO-K9-QOFy_rIB_Dchv8ZTc_YliiLLtn41wIZxLNf6V6YijX8B4oVHiNlQrS5XeLW-8u0_6T7kGv9r2eiNjROc2pGWyQxshfCMOhvSwfKMx1jkQxc9O7TXFP1TjBNr9Dt4v94YImpa-udbd9hoz78f4DkXOBnUfqR6qydi7d_N8Hb23sKIO-6SttWZUxNqlc1FoSbKdiSOKZvZY2ARhCDuDGAbnrEKbFIgS24j03UEltpYcAZveEQByxCQoiDmZQev60elOCIijwxvym-qznd63q3NF_97NjbVFPbeDMen17dkIvZ2i3hfkqr0mPaQpw4CetawrWOYwC7dvfsZb-l0xHD2x8blxkW4hFce1UVdsOH5Jsd8dF_-9vFwUidbyc-LhgLXphj3XC2jwPoBeqIitGqYbNJYwtfE6iYByNre9w7tb8oFQYWf1kqU5c-cpewzTKpPSWzjNjRw0cvk-OSmG_T_CVg3kBR5mYt8oywDhhUR4PGZdx8MgAY8fDw9m5ARFoA3uFMArOCsTDEOb8LkAWM_ucWuT3J4GoHtSBE90k7949tnGU-ypcWkSbG1ZcvcaxTR1NBwl4GF4AisR8rpBrshV_R6JX5nwKMD1itsIUTbzCWnEGfUb3ULrcpV99T17hTIb0-MFoNDqYlNyBcnHDhS_u17j_N25W5zp_NLpF3u2KJqDjQvb6euxI0OPVzQGGAAB6f8_YGAQa1Cg2eoXae0iY6cw5ZoFPomz9BPv1Lei0m3S7vsfw5ERyZhX459gaLF2y8oqsFjbjbi9txDeC4uQ-NMoPvfO0ZEOw=='

    def test_code_request_unwrap(self):
        import poller

        with mock.patch('requests.get'):
            p = poller.poller()
            req = p.unwrap_request(self.test_code_request_raw)

            self.assertIn('id', req)
            self.assertIn('type', req)
            self.assertIn('request_content', req)
            self.assertIn('username', req['request_content'])
            self.assertEqual('wibble', req['request_content']['username'])

    def test_reset_request_unwrap(self):
        import poller

        with mock.patch('requests.get'):
            p = poller.poller()
            req = p.unwrap_request(self.test_reset_request_raw)

            self.assertIn('id', req)
            self.assertIn('type', req)
            self.assertIn('request_content', req)
            self.assertIn('username', req['request_content'])
            self.assertEqual('wibble', req['request_content']['username'])

    def test__send_code__whenCalledWithValidParameters__calls_send_sms(self):
        from ad_connector import search_object, set_password

        with mock.patch('requests.get'):
            p = poller.poller()

            with mock.patch('ad_connector.search_object.search_object', autospec=True, entries=[user_obj()], bound=True, return_value=wibble()) as ldap_conn:
            # with mock.patch('pyad.adquery.ADQuery', side_effect=self.mocked_pyad):
                with mock.patch('requests.post') as post_request:
                    with mock.patch('poller.poller.send_sms') as mocked_sms:
                        p.send_code('wibble', '123')
                        mocked_sms.assert_called()
                        called_args = mocked_sms.call_args_list[0][0]

                        self.assertEqual('123456', called_args[0])
                        self.assertEqual(10, len(called_args[1]))

    def test__poll__whenCalled__callsRequestsURL(self):
        p = poller.poller()

        with mock.patch ('requests.get') as get_request:
            p.poll()

            address = get_request.call_args[0][0]

            get_request.assert_called()
            self.assertIn('/requests', address)

    def test__mock__pyad(self):
        with mock.patch('ad_connector.search_object.search_object', autospec=True, entries=[user_obj()], bound=True, return_value=wibble()) as ldap_conn:
        # with mock.patch('pyad.adquery.ADQuery', side_effect=self.mocked_pyad):
            from ad_connector import search_object

            so = search_object.search_object()
            so.search('test_cn', 'test_domain', 'test_server')
            None

    def test__poll__whenSingleRequestForCodeRetrieved__calls_send_sms(self):
        p = poller.poller()

        with mock.patch('requests.get', side_effect=self.mocked_requests_get_code) as get_request:
            with mock.patch('ad_connector.search_object.search_object', autospec=True, entries=[user_obj()], bound=True,
                            return_value=wibble()) as ldap_conn:
                with mock.patch('poller.poller.send_sms') as mocked_sms:
                    with mock.patch('requests.post'):

                        p.poll()

                        mocked_sms.assert_called()

    def test__poll__whenSingleRequestForCodeRetrieved__callsFrontEndWithValidJSON(self):
        p = poller.poller()

        with mock.patch('requests.get', side_effect=self.mocked_requests_get_code) as get_request:
            with mock.patch('ad_connector.search_object.search_object', autospec=True, entries=[user_obj()], bound=True,
                            return_value=wibble()) as ldap_conn:
                with mock.patch('poller.poller.send_sms') as mocked_sms:
                    with mock.patch('requests.post') as post_request:

                        p.poll()

                        post_request.assert_called()
                        post_body_raw = post_request.call_args[1]['data']

                        try:
                            post_body = json.loads(post_body_raw)
                        except Exception as ex:
                            self.fail('Expected JSON response could not be parsed')

                        self.assertIn('status', post_body)
                        self.assertIn('code_hash', post_body)

class user_obj:
    def __init__(self):
        self.entry_dn = ''
        self.entry_attributes_as_dict = {'sn': ['Smith'], 'givenName': ['Sandra'], 'mail': ['sandra.smith@example.org'], 'mobile': ['123456']}

class wibble:
    def search(self, a, b, c):
        return [{'sn': 'Smith', 'givenName': 'Sandra', 'mail': 'sandra.smith@example.org', 'mobile': '123456'}]
