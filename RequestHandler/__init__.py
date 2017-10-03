import requests
import json

class RequestHandler:
    VALID_SERVICE_TYPES = ['web', 'backend']

    def __init__(self):
        self.services = {}

    def add_service(self, service_name, service_type, location):
        if service_type not in self.VALID_SERVICE_TYPES:
            raise UnrecognisedServiceTypeException()

        self.services[service_name.lower()] = {'type': service_type, 'location': location}

    def make_request(self, service_name, data):
        if service_name not in self.services:
            raise UnrecognisedServiceException()

        type = self.services[service_name.lower()]['type']
        location = self.services[service_name.lower()]['location']

        if type == 'web':
             return self._make_web_request(service_name, location, data)

        elif type == 'backend':
            return self._make_backend_request(service_name, location, data)

    def _make_web_request(self, service_name, location, data):
        web_response = requests.post(location, data=data)

        if web_response.status_code != 200:
            raise WebRequestErrorException()

        if len(web_response.content) == 0:
            raise EmptyResponseException()

        body = web_response.content.decode('utf-8')
        response = json.loads(body)

        return response

    def _make_backend_request(self, service_name, location, data):
        return None

class UnrecognisedServiceException(Exception):
    None

class UnrecognisedServiceTypeException(Exception):
    None

class WebRequestErrorException(Exception):
    None

class EmptyResponseException(Exception):
    None

