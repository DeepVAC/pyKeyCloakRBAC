from pyKeyCloakRBAC.pyrbac import PyRBACOpenID


if __name__ == '__main__':
    server_url = "http://xxxx:xxxx/auth/"
    # 普通用户操作
    username = "wsy01"
    password = "1111"
    client_id = "test_api"
    secret = "xxxx"
    realmname = "demo"
    pid = PyRBACOpenID(server_url, realmname, client_id)
    rpt = pid.get_rpt_token(username, password, client_id, secret)
    print(rpt)
        
    hello = pid.decode_own_token(rpt['access_token'],audience=client_id)
    print(hello)

    pp = pid.verify_rpt_token(rpt['access_token'], audience=client_id)
    print(pp)
