from .keycloak_admin import KeycloakAdmin
from .keycloak_openid import KeycloakOpenID
from .exceptions import raise_error_from_response, KeycloakGetError
from jose import jwt
from .urls_patterns import (
    URL_TOKEN,
)
import json

class PyRBACAdmin(KeycloakAdmin):
    def __init__(self, server_url, username, password, realm_name="master", client_id="admin-cli", verify=True, client_secret_key=None, custom_headers=None, user_realm_name=None, auto_refresh_token=None):
        super().__init__(server_url, username=username, password=password, realm_name=realm_name, client_id=client_id, verify=verify,
                         client_secret_key=client_secret_key, custom_headers=custom_headers, user_realm_name=user_realm_name, auto_refresh_token=auto_refresh_token)
#     def init_permission(self, permissions):
#         # permissions 权限列表
#         # 为client定义角色，代表API权限,clientid为admin-cli
#         self.get_admin_cid()
#         srcp = self.get_all_permissions()
#         if not srcp:
#             toadd = permissions
#         else:
#             toadd = list(set(permissions) - set(srcp.keys()))
#         if not toadd:
#             return self.errormsg("permissions {} already exist.".format(permissions))
#         for permission in toadd:
#             self.add_permission(permission)

#     def get_all_permissions(self):
#         # 获取所有已定义权限
#         self.get_admin_cid()
#         return {key["name"]: key["id"] for key in self.get_client_roles(self.cid)}

#     def add_permission(self, name):
#         # 添加单个权限
#         permissions = self.get_all_permissions()
#         if name in permissions:
#             return self.errormsg("Roles {} already exist.".format(name))
#         url = "admin/realms/{realm-name}/clients/{cid}/roles"
#         params_path = {"realm-name": self.realm_name, "cid": self.cid}
#         data_raw = self.raw_post(url.format(**params_path),
#                                  data=json.dumps({"name": name}))
#         return raise_error_from_response(data_raw, KeycloakGetError, expected_code=201)

#     def delete_permission(self, rolename):
#         # 删除单个权限
#         valid = self.get_all_permissions()
#         if rolename in valid:
#             crid = valid[rolename]
#         else:
#             return self.errormsg("get no permission called {}".format(rolename))
#         url = "admin/realms/{realm-name}/roles-by-id/{role-id}"
#         params_path = {"realm-name": self.realm_name, "role-id": crid}
#         data_raw = self.raw_delete(url.format(**params_path))
#         return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

#     def delete_org(self, orgname):
#         # 删除组织
#         groups = {key["name"]: key["id"] for key in self.get_groups(
#         ) if key["name"].split("_")[0] == orgname}
#         print(groups)
#         for rid in groups.values():
#             self.delete_group(rid)

    def get_all_roles(self):
        return {key["name"]: key["id"] for key in self.get_realm_roles()}

    def get_role_id(self, rolename):
        for role in self.get_realm_roles():
            if rolename == role["name"]:
                return role["id"]

    def add_role(self, rolename):
        # 新增角色
        try:
            return self.create_realm_role({"name": rolename})
        except Exception as e:
            return self.errormsg(str(e))

    def delete_role(self, rolename, force=False):
        # 删除角色
        rid = self.get_role_id(rolename)
        if not rid:
            return self.errormsg("role {} not found".format(rolename))
        if force:
            ...
        else:
            members = self.get_realm_role_members(rolename)
            if members:
                return self.errormsg("{} users in current role".format(len(members)))
        return self.delete_realm_role(rolename)

    def update_role(self, srcname, rolename):
        rid = self.get_role_id(srcname)
        if not rid:
            return self.errormsg("role {} not found".format(srcname))
        if rolename in self.get_all_roles():
            return self.errormsg("rolename {} alread exists".format(rolename))
        self.update_realm_role(srcname, {"name": rolename})

#     def get_role_permissions(self, rolename):
#         rid = self.get_role_id(rolename)
#         if not rid:
#             return self.errormsg("role {} not found".format(rolename))
#         url = "admin/realms/{realm-name}/groups/{rid}/role-mappings/clients/{cid}"
#         self.get_admin_cid()
#         params_path = {"realm-name": self.realm_name,
#                        "rid": rid, "cid": self.cid}
#         data_raw = self.raw_get(url.format(**params_path))
#         return raise_error_from_response(data_raw, KeycloakGetError, expected_code=200)

#     def assign_permissions_to_role(self, rolename, permissions):
#         rid = self.get_role_id(rolename)
#         if not rid:
#             return self.errormsg("role {} not found".format(rolename))
#         allp = self.get_all_permissions()
#         if not allp:
#             return self.errormsg("no permission now,need to init permissions")
#         invalid = list(set(permissions) - set(allp.keys()))
#         if invalid:
#             return self.errormsg("permission {} not in current permissions".format(invalid))
#         srcpermissions = self.get_role_permissions(rolename)
#         srcp = [name["name"] for name in srcpermissions]
#         self.delete_permissions_from_role(rolename, srcp)
#         url = "admin/realms/{realm-name}/groups/{rid}/role-mappings/clients/{cid}"
#         params_path = {"realm-name": self.realm_name,
#                        "cid": self.cid, "rid": rid}
#         payload = [{"id": allp[name], "name": name, "containerId": self.cid}
#                    for name in permissions]
#         data_raw = self.raw_post(url.format(**params_path),
#                                  data=json.dumps(payload))
#         return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

#     def delete_permissions_from_role(self, rolename, permissions):
#         rid = self.get_role_id(rolename)
#         if not rid:
#             return self.errormsg("role {} not found".format(rolename))
#         allp = self.get_all_permissions()
#         toremove = [{"id": allp[name], "name": name,
#                      "containerId": self.cid} for name in permissions]
#         url = "admin/realms/{realm-name}/groups/{rid}/role-mappings/clients/{cid}"
#         params_path = {"realm-name": self.realm_name,
#                        "cid": self.cid, "rid": rid}
#         data_raw = self.raw_delete(url.format(**params_path),
#                                    data=json.dumps(toremove))
#         return raise_error_from_response(data_raw, KeycloakGetError, expected_code=204)

    def assign_role_to_user(self, username, rolename):
        uid = self.get_user_id(username)
        if not uid:
            return self.errormsg("username {} not found".format(username))
        return self.assign_realm_roles(uid, self.get_realm_role(rolename))

    # def delete_realm_user_role(self, username, rolename):
    #     uid = self.get_user_id(username)
    #     if not uid:
    #         return self.errormsg("username {} not found".format(username))
    #     rid = self.get_role_id(rolename)
    #     if not rid:
    #         return self.errormsg("role {} not found".format(rolename))
    #     url = "admin/realms/{realm-name}/users/{uid}/role-mappings/realm"
    #     params_path = {"realm-name": self.realm_name, "uid": uid}
    #     data_raw = self.raw_delete(url.format(**params_path), data=self.get_realm_role(rolename))
    #     print(data_raw)
    #     return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=204)

    def errormsg(self, msg):
        return {"error": msg}

class PyRBACOpenID(KeycloakOpenID):
    def __init__(self, server_url, realm_name, client_id, client_secret_key=None, verify=True, custom_headers=None):
        super().__init__(server_url, realm_name, client_id,
                         client_secret_key=client_secret_key, verify=verify, custom_headers=custom_headers)
        self.verify = verify
        self.pk = self.get_pk()

    def get_pk(self):
        return "-----BEGIN PUBLIC KEY-----\n" + \
            self.public_key() + "\n-----END PUBLIC KEY-----"

    def get_user_token(self, username, password, client_id=None, totp=None, **extra):
        params_path = {"realm-name": self.realm_name}
        payload = {"username": username, "password": password,
                   "client_id": client_id if client_id else self.client_id, "grant_type": "password"}
        if payload:
            payload.update(extra)
        if totp:
            payload["totp"] = totp
        if extra.get("client_secret_key"):
            payload.update({"client_secret": extra.get("client_secret_key")})
        data_raw = self.connection.raw_post(URL_TOKEN.format(**params_path),
                                            data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError)

    def decode_own_token(self, token, audience, algorithms=['RS256'], **kwargs):
        if not kwargs.get('options'):
            kwargs['options'] = {'verify_aud': False, 'verify_exp': False}
        try:
            res = jwt.decode(token, self.pk, algorithms=algorithms,
                             audience=audience, **kwargs)
            return {"res": res}
        except Exception as e:
            return {"error": str(e)}

    def verify_rpt_token(self, token, audience, algorithms=['RS256'], **kwargs):
        try:
            res = jwt.decode(token, self.pk, algorithms=algorithms,
                             audience=audience, **kwargs)
            return True, res.get('authorization')
        except Exception as e:
            print("verify token error:", str(e))
            return False, str(e)
    
    def verify_token_with_url(self, token, audience, url, algorithms=['RS256'], **kwargs):
        try:
            res = jwt.decode(token, self.pk, algorithms=algorithms,
                             audience=audience, **kwargs)
            if res.get('authorization'):
                urls = [item['rsname'] for item in res.get('authorization').get('permissions')]
                if url in urls:
                    return True, url
            return False, "No permission with {}".format(url)
        except Exception as e:
            print("Verify token error:", str(e))
            return False, str(e)

    def get_rpt_token(self, username, password, client_id, client_secret, totp=None, **extra):
        params_path = {"realm-name": self.realm_name}
        self.connection.add_param_headers(
            "Authorization", "Bearer " + self.get_user_token(username, password, client_id, client_secret_key=client_secret).get("access_token"))
        payload = {"audience": client_id,
                   "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket"}
        if payload:
            payload.update(extra)
        if totp:
            payload["totp"] = totp
        data_raw = self.connection.raw_post(URL_TOKEN.format(**params_path),
                                            data=payload)
        return raise_error_from_response(data_raw, KeycloakGetError)
