import requests
import os
import json
from dotenv import load_dotenv
import jwt

load_dotenv()

keycloak_url = os.getenv("KEYCLOAK_URL")
client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET")
client_id = os.getenv("KEYCLOAK_CLIENT_ID")

def getRealmInfo(realm):
    access_token = getMasterAccessToken()
    realm_res = requests.get(f"{keycloak_url}/admin/realms/{realm}", headers={"Authorization": f"Bearer {access_token}"})
    return realm_res.json()

def getClients(realm):
    access_token = getMasterAccessToken()
    realm_res = requests.get(f"{keycloak_url}/admin/realms/{realm}/clients", headers={"Authorization": f"Bearer {access_token}"})
    return realm_res.json()

def getRealmUser(email):
    access_token = getMasterAccessToken()
    user_search_res = requests.get(f"{keycloak_url}/admin/realms/zeron/users?email={email}", headers={"Authorization": f"Bearer {access_token}"})
    user_search_res.raise_for_status()
    user = user_search_res.json()[0]
    if user == None:
        return None
    user_id = user["id"]
    realm_res = requests.get(f"http://localhost:8080/admin/realms/zeron/users/{user_id}", headers={"Authorization": f"Bearer {access_token}"})
    return realm_res.json()

def getRealmRoles():
    access_token = getMasterAccessToken()
    realm_res = requests.get(f"{keycloak_url}/admin/realms/zeron/roles", headers={"Authorization": f"Bearer {access_token}"})
    return realm_res.json()

def getOrgRoles(org):
    access_token = getMasterAccessToken()
    groups_res = requests.get(f"http://localhost:8080/admin/realms/zeron/groups", headers={"Authorization": f"Bearer {access_token}"})
    groups_res.raise_for_status()
    all_groups = groups_res.json()
    org_groups = []
    for group in all_groups:
        try:
            group_res = requests.get(f"http://localhost:8080/admin/realms/zeron/groups/{group['id']}", headers={"Authorization": f"Bearer {access_token}"})
            group_res.raise_for_status()
            group_details = group_res.json()
            if group_details["attributes"] != None and group_details["attributes"]["org"] != None and org in group_details["attributes"]["org"]:
                org_groups.append(group_details)
        except:
            continue
    return org_groups

def updateRoleWithAttribute(role_name, attributes=None):
    access_token = getMasterAccessToken()
    realm_roles = getRealmRoles()
    role = None
    for _role in realm_roles:
        if _role["name"] == role_name:
            role = _role
    if role == None:
        return None
    role_id = role["id"]
    role_details_res = requests.get(f"{keycloak_url}/admin/realms/zeron/roles-by-id/{role_id}", data=json.dumps(role), headers={"Authorization": f"Bearer {access_token}"})
    role_details = role_details_res.json()
    existing_attributes = role_details["attributes"]
    if existing_attributes == None:
        existing_attributes = attributes
    else:
        existing_attributes.update(attributes)
    role_details["attributes"] = existing_attributes
    realm_res = requests.put(f"{keycloak_url}/admin/realms/zeron/roles-by-id/{role_id}", data=json.dumps(role_details), headers={"Authorization": f"Bearer {access_token}"})
    realm_res.raise_for_status()

def createRealmRole(role, desc=None, attributes=None):
    access_token = getMasterAccessToken()
    realm_res = requests.post(f"{keycloak_url}/admin/realms/zeron/roles", data=json.dumps({
            "name": role,
            "description": desc,
        }), headers={"Authorization": f"Bearer {access_token}"})
    realm_res.raise_for_status()
    if attributes:
        updateRoleWithAttribute(role, attributes)

def createRealmUserWithRoles(org, email, roles=None):
    access_token = getMasterAccessToken()
    realm_res = requests.post(f"{keycloak_url}/admin/realms/zeron/users", data=json.dumps({
        "username": email,
        "enabled": True,
        "emailVerified": True,
        "email": email,
        "credentials": [
            {
                "type": "password",
                "value": f"{email}",
                "temporary": False
            }
        ],
        "attributes": {
            "org": [org]
        }
    }), headers={"Authorization": f"Bearer {access_token}"})
    realm_res.raise_for_status()
    if roles != None or len(roles) > 0:
        realm_id = getRealmInfo("zeron")["id"]
        realm_roles = getRealmRoles()
        required_roles = []
        for role in realm_roles:
            if role["name"] in roles:
                required_roles.append({
                    "id": role["id"],
                    "name": role["name"],
                    "composite": False,
                    "clientRole": False,
                    "containerId": realm_id
                })
        user_id = getRealmUser(email)["id"]
        role_mapping_res = requests.post(f"{keycloak_url}/admin/realms/zeron/users/{user_id}/role-mappings/realm", data=json.dumps(required_roles), headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"})
        role_mapping_res.raise_for_status()

def updateUserRole(email, role):
    user_info = getRealmUser(email)
    if user_info == None:
        return None
    user_id = user_info["id"]
    access_token = getMasterAccessToken()
    realm_roles = getRealmRoles()
    required_roles = []
    for _role in realm_roles:
        if _role["name"] == role:
            required_roles.append(_role)
    role_mapping_res = requests.post(f"{keycloak_url}/admin/realms/zeron/users/{user_id}/role-mappings/realm", data=json.dumps(required_roles), headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"})
    role_mapping_res.raise_for_status()

def removeUserRole(email, role):
    user_info = getRealmUser(email)
    if user_info == None:
        return None
    user_id = user_info["id"]
    access_token = getMasterAccessToken()
    realm_roles = getRealmRoles()
    required_roles = []
    for _role in realm_roles:
        if _role["name"] == role:
            required_roles.append(_role)
    role_mapping_res = requests.delete(f"{keycloak_url}/admin/realms/zeron/users/{user_id}/role-mappings/realm", data=json.dumps(required_roles), headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"})
    role_mapping_res.raise_for_status()

def updateUserAttribute(email, attributes):
    user_info = getRealmUser(email)
    if user_info == None:
        return None
    user_id = user_info["id"]
    access_token = getMasterAccessToken()
    user_info["attributes"] = attributes
    realm_res = requests.put(f"{keycloak_url}/admin/realms/zeron/users/{user_id}", data=json.dumps(user_info), headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"})
    realm_res.raise_for_status()

def createGroupWithRoles(org, group_name, roles):
    access_token = getMasterAccessToken()
    realm_res = requests.post(f"{keycloak_url}/admin/realms/zeron/groups", data=json.dumps({
        "name": group_name,
        "attributes": { "org": [org] },
        "realmRoles": roles,
    }), headers={"Authorization": f"Bearer {access_token}"})
    realm_res.raise_for_status()

def getGroupInfo(group_name):
    access_token = getMasterAccessToken()
    group_res = requests.get(f"{keycloak_url}/admin/realms/zeron/groups?search={group_name}", headers={"Authorization": f"Bearer {access_token}"})
    group_res.raise_for_status()
    group_details = group_res.json()[0]
    group_id = group_details["id"]
    group_roles_res = requests.get(f"{keycloak_url}/admin/realms/zeron/groups/{group_id}/role-mappings", headers={"Authorization": f"Bearer {access_token}"})
    group_roles_res.raise_for_status()
    group_roles = group_roles_res.json()
    if (group_roles != {} and group_roles["realmMappings"] != None):
        group_details["roles"] = group_roles["realmMappings"]
    else:
        group_details["roles"] = []
    return group_details

def updateGroupRoles(group_name, roles):
    access_token = getMasterAccessToken()
    group_details = getGroupInfo(group_name)
    group_id = group_details["id"]
    group_existing_roles = group_details["roles"]
    realm_id = getRealmInfo("zeron")["id"]
    realm_roles = getRealmRoles()
    for role in realm_roles:
        if role["name"] in roles:
            group_existing_roles.append({
                "id": role["id"],
                "name": role["name"],
                "composite": False,
                "clientRole": False,
                "containerId": realm_id,
                "description": role["description"],
            })
    realm_res = requests.post(f"{keycloak_url}/admin/realms/zeron/groups/{group_id}/role-mappings/realm", data=json.dumps(group_existing_roles), headers={"Authorization": f"Bearer {access_token}"})
    realm_res.raise_for_status()

def addUserToGroup(group_name, user_email):
    access_token = getMasterAccessToken()
    user_details = getRealmUser(user_email)
    user_id = user_details["id"]
    group_details = getGroupInfo(group_name)
    group_id = group_details["id"]
    realm_res = requests.put(f"{keycloak_url}/admin/realms/zeron/users/{user_id}/groups/{group_id}", headers={"Authorization": f"Bearer {access_token}"})
    realm_res.raise_for_status()

def createGroupWithRoles(org, group_name, roles):
    access_token = getMasterAccessToken()
    realm_res = requests.post(f"{keycloak_url}/admin/realms/zeron/groups", data=json.dumps({
        "name": group_name,
        "attributes": { "org": [org] },
    }), headers={"Authorization": f"Bearer {access_token}"})
    realm_res.raise_for_status()
    updateGroupRoles(group_name, roles)

def authUser(email, password):
    auth_res = requests.post(
        f"{keycloak_url}/realms/zeron/protocol/openid-connect/token",
        data={
            "client_id": "admin-cli",
            "username": email,
            "password": password,
            "grant_type": "password",
        }, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    return auth_res.json()

def getPublicKey():
    access_token = getMasterAccessToken()
    realm_res = requests.get(f"{keycloak_url}/admin/realms/zeron/keys", headers={"Authorization": f"Bearer {access_token}"})
    keys = realm_res.json()["keys"]
    key_data = None
    for key in keys:
        if key["algorithm"] == "RS256":
            key_data = key["publicKey"]
    formatted_key = f"-----BEGIN PUBLIC KEY-----\n{key_data}\n-----END PUBLIC KEY-----"
    return formatted_key

def getUserRoles(user_id):
    access_token = getMasterAccessToken()
    roles = []
    realm_res = requests.get(f"{keycloak_url}/admin/realms/zeron/users/{user_id}/role-mappings/realm", headers={"Authorization": f"Bearer {access_token}"})
    roles = realm_res.json()
    composite_roles_res = requests.get(f"{keycloak_url}/admin/realms/zeron/users/{user_id}/role-mappings/realm/composite", headers={"Authorization": f"Bearer {access_token}"})
    composite_roles = composite_roles_res.json()
    roles.extend(composite_roles)
    return roles

def decodeUserToken(access_token):
    publicKeyBinary = getPublicKey().encode("ascii")
    token_data = jwt.decode(access_token, publicKeyBinary, algorithms=["RS256"])
    roles = getUserRoles(token_data["sub"])
    org = getRealmUser(token_data["email"])["attributes"]["org"][0]
    return {
        "id": token_data["sub"],
        "email": token_data["email"],
        "roles": roles,
        "scope": token_data["scope"],
        "org": org,
    }

def checkRoles(existing_roles, required_roles):
    user_roles = []
    for _role in existing_roles:
        user_roles.append(_role["name"])

    for _role in user_roles:
        if _role in required_roles:
            return True
    return False

def checkRoleAttribute(role_name, attributes):
    access_token = getMasterAccessToken()
    realm_roles = getRealmRoles()
    role = None
    for _role in realm_roles:
        if _role["name"] == role_name:
            role = _role
    if role == None:
        return False
    role_id = role["id"]
    role_details_res = requests.get(f"{keycloak_url}/admin/realms/zeron/roles-by-id/{role_id}", data=json.dumps(role), headers={"Authorization": f"Bearer {access_token}"})
    role_details = role_details_res.json()
    existing_attributes = role_details["attributes"]
    if existing_attributes == None:
        return False
    for key, value in attributes.items():
        if key not in existing_attributes:
            return False
        if value not in existing_attributes[key]:
            return False
    return True

def checkUserAttributes(email, attributes):
    user_info = getRealmUser(email)
    if user_info == None:
        return False
    user_attributes = user_info["attributes"]
    if user_attributes == None:
        return False
    for key, value in attributes.items():
        if key not in user_attributes:
            return False
        if user_attributes[key] == None or len(user_attributes[key]) == 0:
            return False
        isValueExist = False
        for attribute_value in user_attributes[key]:
            if value in attribute_value:
                isValueExist = True
                break
        if not isValueExist:
            return False
    return True

def checkUserOrg(email, org):
    user_info = getRealmUser(email)
    if user_info == None:
        return False
    user_attributes = user_info["attributes"]
    if user_attributes == None:
        return False
    if "org" not in user_attributes:
        return False
    if user_attributes["org"] == None or len(user_attributes["org"]) == 0:
        return False
    isValueExist = False
    for attribute_value in user_attributes["org"]:
        if org in attribute_value:
            isValueExist = True
            break
    if not isValueExist:
        return False
    return True

def getMasterAccessToken():
    res = requests.post(f"{keycloak_url}/realms/master/protocol/openid-connect/token", data={
        "client_secret": client_secret,
        "client_id": client_id,
        "grant_type": "client_credentials"
        }, headers={"Content-Type": "application/x-www-form-urlencoded"})
    access_token = res.json()["access_token"]
    return access_token
