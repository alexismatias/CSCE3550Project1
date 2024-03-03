from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import jwt

app = Flask(__name__)
#public_key, private_key = rsa.newkeys(1024)

#with open ("public.pem", "wb") as f: #Creating the public key
#    f.write(public_key.save_pkcs1("PEM"))

#with open ("private.pem", "wb") as f: #Creating the private key
#    f.write(private_key.save_pkcs1("PEM"))

#kid = key_id()
#expiry_timestamp = int(time.time()) + 60 # one minute
#private_key = rsa.generate_private_key(
#    public_exponent=65537,
#    key_size=2048,
#)
   
keys = {}

def gen_rsa(): #Generating rsa key
    private_key = rsa.gen_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    keyID = str(len(keys) + 1)
    exp_time = datetime.utcnow() + timedelta(seconds=60) #expiring 50s
    keys[keyID] = (public_key, private_key, exp_time)
    return keyID

#JWKS endpoint
@app.route('/.well-known/jwks.json', methods=['GET']) 
def jwks():
    jwks_keys = []
    for kid, (public_key, _, exp_time) in keys.items():
        if datetime.utcnow() < exp_time:
            jwks_keys.append({
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": public_key.public_numbers().n,
                "e": public_key.public_numbers().e
            })
    return jsonify(keys=jwks_keys)

#Authentication endpoint
@app.route('/auth', methods=['POST'])
def authenticate():
    expired = request.args.get('expired')
    if expired:
        key_id = list(keys.keys())[0]  
    else:
        key_id = gen_rsa()
    private_key = keys[key_id][1]
    exp_time = keys[key_id][2]
    payload = {'username': 'user', 'exp': exp_time}
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': key_id})
    return jsonify(token=token)

if __name__ == '__main__':
    app.run(port=8080)