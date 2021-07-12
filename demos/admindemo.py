import os
pwd = os.getcwd()
import sys
sys.path.append(pwd.replace('/demos', ''))
from pyKeyCloakRBAC.pyrbac import PyRBACAdmin

# 配置是否需要演示
testdict = {'roletest': True, 'usertest': True, 'resourcetest': True,
            'permissiontest': True, 'policytest': True, 'user_role': True,
            'role_permission': True}

if __name__ == '__main__':
    # keycloak实际地址
    server_url = "http://host:port/auth/"
    # 管理员操作
    username = "realmadmin"
    password = "1111"
    client_id = "admin-cli"
    realmname = "demo"
    pa = PyRBACAdmin(server_url, username, password,
                     realm_name=realmname, verify=False)

    username = "Alice"
    password = "abcdefg"
    rolename = "svip"
    resource_client = "test_api"
    resource = "/api/v1/face"
    # 操作角色
    if testdict['roletest']:
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
    
    # 操作策略
    if testdict['policytest']:
        print('创建策略：')
        print('\t', pa.create_policy(resource_client, rolename, rolename))
        print('获取所有策略信息：')
        print('\t', pa.get_client_policies(resource_client))
        # print('删除策略信息：')
        # print('\t', pa.delete_policy(resource_client, rolename))

    # 操作用户
    if testdict['usertest']:
        print('获取所有用户信息：')
        for user in pa.get_users():
            print('\t', user)
        print("新增用户 {}:".format(username))
        payload = {"enabled": True, "emailVerified": "", "username": username,
                   "credentials": [{"type": "password", "value": password, "temporary": False}]}
        try:
            uid = pa.create_user(payload, exist_ok=False)
            print("\t", uid)
        except Exception as e:
            print("\t", str(e))
        print("获取用户 {} id：".format(username))
        uid = pa.get_user_id(username)
        print("\t", uid)
        print('获取用户信息:')
        print('\t', pa.get_user(uid))
        print('修改用户密码：')
        new_password = 'newpassword'
        print('\t', pa.set_user_password(uid, new_password, temporary=False))
        print('更新用户信息：')
        new_info = {'emailVerified': True, 'attributes': {'count': ['999']}}
        print('\t', pa.update_user(uid, new_info))
        print('\t', pa.get_user(uid))
        # print('删除用户 {}'.format(username))
        # print('\t', pa.delete_user(uid))

    # 操作用户和角色
    if testdict['user_role']:
        print("用户{}和角色{}关联：".format(username, rolename))
        print("\t", pa.assign_role_to_user(username, rolename))
        print("获取角色 {} 下的用户：".format(rolename))
        print("\t", pa.get_realm_role_members(rolename))
        print('获取用户{}的角色：'.format(username))
        print('\t', pa.get_realm_roles_of_user(pa.get_user_id(username)))
        print("取消用户{}和角色{}的关联:".format(username, rolename))
        print("\t", pa.delete_realm_user_role(username, rolename))

    # 操作资源
    if testdict['resourcetest']:
        print("创建资源: ")
        print("\t", pa.create_resource(resource_client, resource))
        print("获取resource_client {}的所有resource：".format(resource_client))
        print("\t", pa.get_resources(resource_client))
    
    # 操作权限
    if testdict['permissiontest']:
        print("创建权限: ")
        print('\t', pa.create_client_permission(resource_client, resource))
        print("获取resource_client {}的所有permission：".format(resource_client))
        print("\t", pa.get_permissions(resource_client))
        
    # 操作角色与权限
    if testdict["role_permission"]:
        print('角色{}绑定权限{}: '.format(rolename, resource))
        print("\t", pa.op_permission_with_role(resource_client, resource, rolename))
        print('获取权限{}关联的角色：'.format(resource))
        print('\t', pa.get_permission_roles(resource_client, resource))
        # print('角色{}取消权限{}: '.format(rolename, resource))
        # print("\t", pa.op_permission_with_role(resource_client, resource, rolename, op="delete"))
        print('获取角色{}的所有权限: '.format(rolename))
        print("\t", pa.get_role_permissions(resource_client, rolename))