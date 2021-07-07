import os
pwd = os.getcwd()
import sys
sys.path.append(pwd.replace('/demos', ''))
from pyKeyCloakRBAC.pyrbac import PyRBACAdmin

if __name__ == '__main__':
    # server_url = "http://xxxx:xxxx/auth/"
    server_url = "http://114.115.170.142:8080/auth/"
    # 管理员操作
    username = "realmadmin"
    password = "1111"
    client_id = "admin-cli"
    realmname = "demo"
    pa = PyRBACAdmin(server_url, username, password,
                     realm_name=realmname, verify=False)
    # 角色操作
    roletest = True # 改为False，跳过角色操作，下同
    if roletest:
        rolename = "svip"
        print("获取所有角色：")
        print("\t", pa.get_all_roles())
        try:
            print("新增角色 {}：".format(rolename))
            print("\t", pa.create_role(rolename))
        except Exception as e:
            print("\t", str(e))
        print("获取角色 {} ID: ".format(rolename))
        print("\t", pa.get_role_id(rolename))
        # print("更新角色信息:")
        # newname = 'newsvip'
        # print("\t", pa.update_role(rolename, newname))
        # print("删除角色信息：")
        # print("\t", pa.delete_role(newname))
    
    # # 用户操作
    # usertest = True
    # if usertest:
    #     username = "Alice"
    #     password = "abcdefg"
    #     print("新增用户 {}:".format(username))
    #     payload = {"enabled": True, "emailVerified": "", "username": username,
    #                "credentials": [{"type": "password", "value": password, "temporary": False}]}
    #     try:
    #         uid = pa.create_user(payload, exist_ok=False)
    #         print("\t", uid)
    #     except Exception as e:
    #         print("\t", str(e))
    #     print("获取用户 {} id：".format(username))
    #     print("\t", pa.get_user_id(username))
    # # 操作用户和角色
    # print("分配给用户角色：")
    # print("\t", pa.assign_role_to_user(username, rolename))
    # # print("删除用户角色:")
    # # print("\t", pa.delete_realm_user_role(username, rolename))
    # print("获取角色 {} 下的所有用户：".format(rolename))
    # print("\t", pa.get_realm_role_members(rolename))

    # 资源操作
    resourcetest = True
    if resourcetest:
        resource_client = "test_api"
        resource = "/api/v1/face"
        print("创建资源: ")
        print("\t", pa.create_resource(resource_client, resource))
        print("创建权限: ")
        print('\t', pa.create_client_permission(resource_client, resource))
        print("获取resource_client {}的所有resource：".format(resource_client))
        print("\t", pa.get_resources(resource_client))
        print("获取resource_client {}的所有permission：".format(resource_client))
        print("\t", pa.get_permissions(resource_client))
        # # 权限操作,权限基于资源，可以绑定角色策略。
        # print('角色绑定权限: ')
        # print("\t", pa.assign_permission_to_role(resource_client, resource, rolename))

        ...