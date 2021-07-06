from pyKeyCloakRBAC.pyrbac import PyRBACAdmin

if __name__ == '__main__':
    server_url = "http://xxxx:xxxx/auth/"
    # 管理员操作
    username = "realmadmin"
    password = "1111"
    client_id = "admin-cli"
    realmname = "demo"
    pa = PyRBACAdmin(server_url, username, password,
                     realm_name=realmname, verify=False)
    # 角色操作
    rolename = "svip"
    print("获取所有角色：")
    realm_roles = pa.get_all_roles()
    print("\t", realm_roles)
    print("新增角色 {}：".format(rolename))
    res = pa.create_role(rolename)
    print("\t", res)
    print("获取角色 {} ID: ".format(rolename))
    print("\t", pa.get_role_id(rolename))
    print("获取 role based policy：")
    print("\t", pa.get_client_policies("test_api"))
    # 更新角色信息
    # print(pa.update_role(rolename, "newsvip"))
    # 删除角色,当有角色和用户绑定时，默认不删除
    # print("删除角色 delete_role:")
    # print(pa.delete_role(rolename))
    # 用户操作
    username = "Alice"
    password = "abcdefg"
    print("新增用户 {}:".format(username))
    payload = {"enabled": True, "emailVerified": "", "username": username,
               "credentials": [{"type": "password", "value": password, "temporary": False}]}
    try:
        uid = pa.create_user(payload, exist_ok=False)
        print("\t", uid)
    except Exception as e:
        print("\t", str(e))
    print("获取用户 {} id：".format(username))
    print("\t", pa.get_user_id(username))
    # 操作用户和角色
    print("分配给用户角色：")
    print("\t", pa.assign_role_to_user(username, rolename))
    # print("删除用户角色:")
    # print("\t", pa.delete_realm_user_role(username, rolename))
    print("获取角色 {} 下的所有用户：".format(rolename))
    print("\t", pa.get_realm_role_members(rolename))
    # 资源操作,同时初始化对应permission
    resource_client = "test_api"
    resource = "/api/v1/face"
    try:
        print("创建资源: ")
        print("\t", pa.create_resource(resource_client, resource))
        print('\t', pa.create_client_permission(resource_client, resource))
    except Exception as e:
        print("\t", str(e))
    print("获取resource_client {}的所有api：".format(resource_client))
    print("\t", pa.get_resources(resource_client))
    # 权限操作,权限基于资源，可以绑定角色策略。
    print('角色绑定权限: ')
    print("\t", pa.assign_permission_to_role(resource_client, resource, rolename))


