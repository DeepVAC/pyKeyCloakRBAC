# pyKeyCloakRBAC
RBAC python implementation based on Keycloak

# 概念

## 角色和策略

* 本项目中的角色，在keycloak中表现为realm role,同时，对应的策略和角色名相同。

### 接口

* [x] 新增角色
* [x] 删除角色
* [x] 更新角色名称
* [x] 获取所有角色
* [x] 创建策略
* [x] 删除策略
* [x] 获取策略

## 资源和权限

* 本项目中的权限，在keycloak中表现为client的Resource和Permission。

* client即为实际提供服务的服务器。

* Resource和Permission的name定义为服务的url相对路径。

### 接口
* [x] 新增资源
* [x] 获取所有资源
* [x] 新增权限
* [x] 获取所有权限

## 用户

* 本项目中的用户对用keycloak中的realm user。
### 接口
* [x] 新增用户
* [x] 删除用户
* [x] 修改用户密码
* [x] 更新用户信息
* [x] 获取所有用户信息
* [x] 获取用户信息
## 角色和权限

* 本项目中的角色及权限绑定，使用keycloak中client的Policy进行指定。
* Policy的name和realm role的名字相同。

### 接口

* [x] 角色和权限关联
* [x] 取消角色和权限关联
* [ ] 获取角色的权限
* [x] 获取权限关联的角色

## 用户和角色

### 接口

* [x] 用户和角色关联
* [x] 取消用户和角色的关联
* [x] 获取角色下的用户
* [x] 获取用户的角色