from flask import Flask, request
from pyKeyCloakRBAC import pyrbac
pa = pyrbac.PyRBACOpenID(server_url="http://xxxx:xxxx/auth/",
                         realm_name="demo", client_id="admin-cli", client_secret_key="xxxx", verify=False)
app = Flask(__name__)


@app.route('/api/v1/face')
def face():
    token = request.headers.get("Authorization")
    print(token)
    if not token:
        return "Token is required."
    res = pa.verify_token_with_url(token[7:], "test_api", "/api/v1/face")
    if not res[0]:
        return res[1]
    return "/api/v1/face is alowed."

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5010)
