import unittest
import mock
from RequestHandler import *

class tests_RequestHandler(unittest.TestCase):
    def setUp(self):
        None

    def mocked_requests_post(self, body=None, status_code=200, *args, **kwargs):
        class MockResponse:
            def __init__(self, text, status_code):
                self.text = text
                self.content = self.text.encode('utf-8')
                self.status_code = status_code

            def json(self):
                return self.json_data

        return MockResponse(body, status_code)

    def test__add_service__whenCalledWithHTTPService__registersServiceSuccessfully(self):
        rh = RequestHandler()

        rh.add_service('http_service', 'web', 'set_password')

        self.assertIn('http_service', rh.services)

    def test__add_service__whenCalledWithBackendService__registersServiceSuccessfully(self):
        rh = RequestHandler()

        rh.add_service('backend_service', 'backend', 'set_password')

        self.assertIn('backend_service', rh.services)

    def test__add_service__whenCalledWithInvalidService__raisesUnrecognisedServiceTypeException(self):
        rh = RequestHandler()

        with self.assertRaises(UnrecognisedServiceTypeException):
            rh.add_service('invalid_service', 'invalid_service_type', 'somewhere')

    def test__make_request__whenCalledWithWebService__makesPOSTRequestToServiceLocationWithData(self):
        rh = RequestHandler()

        with mock.patch('requests.post') as mocked_post:
            rh.add_service('test_http_service', 'web', 'https://mythical.service.com/webservice')
            result = rh.make_request('test_http_service', {'test': 123})

            mocked_post.assert_called()

    def test__make_request__whenCalledWithWebServiceThatReturnsEmptyBody__raisesEmptyResponseException(self):
        rh = RequestHandler()

        with mock.patch('requests.post', side_effect=self.mocked_requests_post) as mocked_post:
            rh.add_service('test_http_service', 'web', 'https://mythical.service.com/webservice')

            with self.assertRaises(EmptyResponseException):
                rh.make_request('test_http_service', {'test': 123})





