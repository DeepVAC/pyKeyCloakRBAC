from .keycloak_admin import KeycloakAdmin
from .keycloak_openid import KeycloakOpenID
from .exceptions import raise_error_from_response, KeycloakGetError
from jose import jwt
from .urls_patterns import (
    URL_TOKEN,
    URL_ADMIN_USER_REALM_ROLES,
    URL_ADMIN_CLIENT_AUTHZ_RESOURCES
)
import json


class PyRBACAdmin(KeycloakAdmin):
    def __init__(self, server_url, username, password, realm_name="master", client_id="admin-cli", verify=True, client_secret_key=None, custom_headers=None, user_realm_name=None, auto_refresh_token=None):
        super().__init__(server_url, username=username, password=password, realm_name=realm_name, client_id=client_id, verify=verify,
                         client_secret_key=client_secret_key, custom_headers=custom_headers, user_realm_name=user_realm_name, auto_refresh_token=auto_refresh_token)
    # 角色 与 策略

    def create_role(self, rolename):
        try:
            return self.create_realm_role({"name": rolename})
        except Exception as e:
            return self.errormsg(str(e))

    def delete_role(self, rolename, force=False):
        if force:
            ...
        else:
            members = self.get_realm_role_members(rolename)
            if members:
                return self.errormsg("{} users in current role".format(len(members)))
        return self.delete_realm_role(rolename)

    def get_role_id(self, rolename):
        for role in self.get_realm_roles():
            if rolename == role["name"]:
                return role["id"]

    def update_role(self, srcname, newname):
        roles = self.get_all_roles()
        if roles.get(srcname) and not roles.get(newname):
            return self.update_realm_role(srcname, {"name": newname})
        else:
            return self.errormsg("Please try other role name.")

    def get_all_roles(self):
        return {key["name"]: key["id"] for key in self.get_realm_roles()}

    def get_policy_id(self, client_id, policy):
        url = "admin/realms/{realm-name}/clients/{cid}/authz/resource-server/policy/search?name={policy}"
        cid = self.get_client_id(client_id)
        params_path = {'realm-name': self.realm_name,
                       'cid': cid, 'policy': policy}
        raw_data = self.raw_get(url.format(**params_path))
        if raw_data.status_code == 200:
            pid = raw_data.json()['id']
        else:
            pid = None
        return pid

    def get_client_policies(self, client_id):
        url = "admin/realms/{realm-name}/clients/{cid}/authz/resource-server/policy?permission=false"
        params_path = {"realm-name": self.realm_name,
                       "cid": self.get_client_id(client_id)}
        data_raw = self.raw_get(url.format(**params_path))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def create_policy(self, client_id, policyname, rolename):
        try:
            rid = self.get_role_id(rolename)
            payload = {"type": "role", "logic": "POSITIVE",
                       "decisionStrategy": "AFFIRMATIVE", "name": policyname, "roles": [{"id": rid}]}
            cid = self.get_client_id(client_id)
            url = "admin/realms/{realm-name}/clients/{cid}/authz/resource-server/policy/role"
            params_path = {"realm-name": self.realm_name, "cid": cid}
            data_raw = self.raw_post(url.format(**params_path),
                                     data=json.dumps(payload))
            return raise_error_from_response(data_raw, KeycloakGetError)
        except Exception as e:
            return self.errormsg(str(e))

    def delete_policy(self, client_id, policyname):
        try:
            url = 'admin/realms/{realm-name}/clients/{cid}/authz/resource-server/policy/{pid}'
            params_path = {"realm-name": self.realm_name, "cid": self.get_client_id(
                client_id), 'pid': self.get_policy_id(client_id, policyname)}
            rawdata = self.raw_delete(url.format(**params_path))
            return raise_error_from_response(rawdata, KeycloakGetError)
        except Exception as e:
            return self.errormsg(str(e))

    # 资源 与 权限
    def create_resource(self, client_id, resource, displayName="default"):
        try:
            payload = {"uris": [resource],
                       "name": resource, "displayName": displayName}
            cid = self.get_client_id(client_id)
            params_path = {"realm-name": self.realm_name, "id": cid}
            data_raw = self.raw_post(URL_ADMIN_CLIENT_AUTHZ_RESOURCES.format(**params_path),
                                     data=json.dumps(payload))
            return raise_error_from_response(data_raw, KeycloakGetError, expected_codes=[201])
        except Exception as e:
            return self.errormsg(str(e))

    def create_client_permission(self, client_id, resource):
        try:
            cid = self.get_client_id(client_id)
            url = "admin/realms/{realm-name}/clients/{cid}/authz/resource-server/permission/resource"
            payload = {"type": "resource", "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE",
                       "name": resource, "resources": [self.get_resource_id(client_id, resource)], "policies": []}
            params_path = {"realm-name": self.realm_name, "cid": cid}
            data_raw = self.raw_post(url.format(
                **params_path), data=json.dumps(payload))
            return raise_error_from_response(data_raw, KeycloakGetError)
        except Exception as e:
            return self.errormsg(str(e))

    def get_resources(self, client_id):
        cid = self.get_client_id(client_id)
        return [item['name'] for item in self.get_client_authz_resources(cid)]

    def get_resource_id(self, client_id, resourcename):
        url = "admin/realms/{realm-name}/clients/{cid}/authz/resource-server/resource/search?name={rn}"
        params_path = {'realm-name': self.realm_name,
                       'cid': self.get_client_id(client_id), 'rn': resourcename}
        raw_data = self.raw_get(url.format(**params_path))
        if raw_data.status_code == 200:
            return raw_data.json()['_id']
        else:
            raise Exception("Resource {} is not exist.".format(resourcename))

    def get_permissions(self, client_id, permission=None):
        cid = self.get_client_id(client_id)
        if not permission:
            url = "admin/realms/{realm-name}/clients/{cid}/authz/resource-server/permission"
            params_path = {"realm-name": self.realm_name, "cid": cid}
        else:
            url = 'admin/realms/{realm-name}/clients/{cid}/authz/resource-server/policy/search?name={pname}'
            params_path = {'realm-name': self.realm_name,
                           'cid': cid, 'pname': permission}
        raw_data = self.raw_get(url.format(**params_path))
        return raise_error_from_response(raw_data, KeycloakGetError)

    def delete_permission(self, client_id, permission):
        url = 'admin/realms/{realm-admin}/clients/{cid}/authz/resource-server/permission/{pid}'
        params_path = {'realm-name': self.realm_name, 'cid': self.get_client_id(
            client_id), 'pid': self.get_permissions(client_id, permission)['id']}
        raw_data = self.raw_delete(url.format(**params_path))
        return raise_error_from_response(raw_data, KeycloakGetError)

    # 角色和权限操作
    def op_permission_with_role(self, client_id, permission, role, op="assign"):
        url = 'admin/realms/{realm-name}/clients/{cid}/authz/resource-server/permission/resource/{pid}'
        perm = self.get_permissions(client_id, permission)
        src_roles = self.get_permission_roles(client_id, permission)
        src_role_ids = [rid['id'] for rid in src_roles]
        npoid = self.get_policy_id(client_id, role)
        payload = {"id": perm['id'], "name": permission, "type": "resource",
                   "logic": "POSITIVE", "decisionStrategy": "AFFIRMATIVE"}
        params_path = {'realm-name': self.realm_name,
                       'pid': perm['id'], 'cid': self.get_client_id(client_id)}
        if op == "assign":
            if npoid in src_role_ids:
                return {}
            else:
                src_role_ids.append(npoid)
        else:
            if npoid not in src_role_ids:
                return {}
            else:
                src_role_ids.remove(npoid)
        payload["resources"] = [self.get_resource_id(client_id, permission)]
        payload["policies"] = src_role_ids
        data_raw = self.raw_put(url.format(
            **params_path), data=json.dumps(payload))
        return raise_error_from_response(data_raw, KeycloakGetError)

    def get_role_permissions(self, client_id, rolename):
        client_settings = self.get_client_authz_settings(
            self.get_client_id(client_id)).json()
        policies = client_settings.get("policies")
        permissions = []
        role = None
        for rolep in policies:
            if rolep['type'] == 'role' and not role:
                if rolep['name'] == rolename:
                    role = rolep
            else:
                if rolep['type'] == 'resource':
                    rolepolicies = rolep['config'].get(
                        'applyPolicies') if rolep['config'].get('applyPolicies') else []
                    permissions.extend(
                        [{'id': rolep['id'], 'name': rolep['name']}] if rolename in rolepolicies else [])
        role['permissions'] = permissions
        return role

    def get_permission_roles(self, client_id, permission):
        url = 'admin/realms/{realm-name}/clients/{cid}/authz/resource-server/policy/{pid}/associatedPolicies'
        params_path = {'realm-name': self.realm_name, 'cid': self.get_client_id(
            client_id), 'pid': self.get_permissions(client_id, permission)['id']}
        rawdata = self.raw_get(url.format(**params_path))
        return raise_error_from_response(rawdata, KeycloakGetError)

    # 角色和用户
    def assign_role_to_user(self, username, rolename):
        uid = self.get_user_id(username)
        if not uid:
            return self.errormsg("username {} not found".format(username))
        return self.assign_realm_roles(uid, self.get_realm_role(rolename))

    def delete_realm_user_role(self, username, rolename):
        uid = self.get_user_id(username)
        if not uid:
            return self.errormsg("username {} not found".format(username))
        rid = self.get_role_id(rolename)
        if not rid:
            return self.errormsg("role {} not found".format(rolename))
        data = [self.get_realm_role(rolename)]
        params_path = {"realm-name": self.realm_name, "id": uid}
        data_raw = self.raw_delete(URL_ADMIN_USER_REALM_ROLES.format(**params_path),
                                   data=json.dumps(data))
        return raise_error_from_response(data_raw, KeycloakGetError)

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
                urls = [item['rsname']
                        for item in res.get('authorization').get('permissions')]
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
