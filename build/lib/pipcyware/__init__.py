import base64
import hashlib
import hmac
import time
import requests
import urllib
import json


class CyClient():

    def __init__(self, base_url: str, access_id: str, secret_key: str, timeout:int = 30):
        self.base_url = base_url
        self.access_id = access_id
        self.secret_key = secret_key
        self.timeout = timeout

    def generate_signature(self, access_id, secret_key):
        expires = int(time.time() +15)
        to_sign = '{}\n{}'.format(access_id, expires)
        return base64.b64encode(
            hmac.new(
                secret_key.encode('utf-8'),
                to_sign.encode('utf-8'),
                hashlib.sha1
            ).digest()).decode("utf-8"), expires

    def get(self, endpoint:str, params = {}):
        signature, expires= self.generate_signature(self.access_id, self.secret_key)
        auth = {
            'AccessID': self.access_id,
            'Expires': expires,
            'Signature': signature
        }
        all_params = self.mergeDict(auth, params)
        url = self.base_url + endpoint + '?' + urllib.parse.urlencode(all_params)

        try:
          response = requests.request("GET", url, timeout=self.timeout)
          response.raise_for_status()
          return self.loadJSON(response.text)

        except requests.exceptions.HTTPError as error:
          return error

    def post(self, endpoint:str, data: object, params = {}):
        signature, expires= self.generate_signature(self.access_id, self.secret_key)
        auth = {
            'AccessID': self.access_id,
            'Expires': expires,
            'Signature': signature
        }
        all_params = self.mergeDict(auth, params)
        url = self.base_url + endpoint + '?' + urllib.parse.urlencode(all_params)

        try:
          if isinstance(data, str):
              response = requests.request("POST", url, data=data, timeout=self.timeout)
              return self.loadJSON(response.text)
          elif isinstance(data, dict):
              response = requests.request("POST", url, json=data, timeout=self.timeout)
              return self.loadJSON(response.text)
          else:
              return "Error: return data is not String or Dictionary"

        except requests.exceptions.HTTPError as error:
          return error

    def mergeDict(self, dict1, dict2):
        res = {**dict1, **dict2}
        return res

    def loadJSON(self, response: str):
        try:
            obj = json.loads(response)
            # reserved for later if we want to set a flag for text vs obj return
            # formatted = json.dumps(obj, indent=4)
            return obj
        except:
            # is not JSON
            return response

    def __str__(self):
        return f"Base URL: {self.base_url}"
