import unittest
import requests
import json
import time

class TestSuite(unittest.TestCase):

    def setUp(self):
        self.base_url = 'http://127.0.0.1:8080'

    def test_jwks_endpoint(self):
        response = requests.get(f'{self.base_url}/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)

        jwks_data = response.json()
        self.assertIn('keys', jwks_data)
        keys = jwks_data['keys']

        for key in keys:
            self.assertIn('kid', key)
            self.assertIn('kty', key)
            self.assertIn('alg', key)
            self.assertIn('use', key)
            self.assertIn('n', key)
            self.assertIn('e', key)

    def test_auth_endpoint(self):
        response = requests.post(f'{self.base_url}/auth')
        self.assertEqual(response.status_code, 200)

        auth_data = response.json()
        self.assertIn('token', auth_data)
        token = auth_data['token']

        decoded_token = jwt.decode(token, verify=False)
        self.assertIn('exp', decoded_token)

    def test_expired_auth_endpoint(self):
        response = requests.post(f'{self.base_url}/auth?expired=true')
        self.assertEqual(response.status_code, 200)

        auth_data = response.json()
        self.assertIn('token', auth_data)
        token = auth_data['token']

        # Sleep for a while to simulate an expired token
        time.sleep(2)

        # Verify that the token is expired
        with self.assertRaises(jwt.ExpiredSignatureError):
            jwt.decode(token, verify=False)

if __name__ == '__main__':
    unittest.main()
