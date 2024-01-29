from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from services.keycloak import getMasterAccessToken, createRealmUserWithRoles, decodeUserToken, checkRoles, getRealmRoles, createRealmRole, createGroupWithRoles, addUserToGroup, getOrgRoles, checkRoleAttribute, updateUserAttribute, updateUserRole, checkUserOrg
from fastapi.middleware.cors import CORSMiddleware
import random
import string

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    access_token = getMasterAccessToken()
    if not access_token:
        return {"message": "Error getting access token"}
    return {"message": "FastAPI Auth Service"}

plan_roles = {
    "basic": ["InternalTicketScreen"],
    "advanced": ["InternalTicketScreen", "Compliance"]
}

class OrgPayment(BaseModel):
    plan: str
    name:str
    # name_slug: str
    email: str

@app.post("/api/orgs")
async def create_org(org_payment: OrgPayment):
    try:
        roles = plan_roles[org_payment.plan]
        roles.append("org_admin")
        org_slug = ''.join(random.choices(string.ascii_letters, k=8))
        createRealmUserWithRoles(org_slug, org_payment.email, roles)
        return {"message": "Org created successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/orgs/users")
async def create_org_user(request: Request):
    required_roles = ["org_admin"]

    try:
        admin_data = decodeUserToken(request.headers.get('Authorization').split()[1])
        if not checkRoles(admin_data["roles"], required_roles):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )

        request_data = await request.json()
        requiredRoles = request_data["roles"]
        existingRoles = getRealmRoles()
        for role in requiredRoles:
            isRoleExist = False
            for existingRole in existingRoles:
                if existingRole["name"] == role:
                    isRoleExist = True
                    break
            if not isRoleExist:
                createRealmRole(role, "Org admin created role")
        createRealmUserWithRoles(admin_data["org"], request_data["email"], requiredRoles)
        return {"message": "Org user created successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/orgs/users/attributes")
async def assign_user_attributes(request: Request):
    required_roles = ["org_admin"]

    try:
        admin_data = decodeUserToken(request.headers.get('Authorization').split()[1])
        if not checkRoles(admin_data["roles"], required_roles):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )

        request_data = await request.json()
        requiredUser = request_data["email"]
        if not checkUserOrg(requiredUser, admin_data["org"]):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )
        requiredAttributes = request_data["attributes"]
        requiredAttributes["org"] = [admin_data["org"]]
        updateUserAttribute(requiredUser, requiredAttributes)
        return {"message": "Org user attributes assigned successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/orgs/roles")
async def create_org_role_or_group(request: Request):
    required_roles = ["org_admin"]

    try:
        admin_data = decodeUserToken(request.headers.get('Authorization').split()[1])
        if not checkRoles(admin_data["roles"], required_roles):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )

        request_data = await request.json()
        requiredRoleName = request_data["role"]
        if (request_data["roles"]):
            requiredRoles = request_data["roles"]
            realm_roles = getRealmRoles()
            for _role in requiredRoles:
                isExist = False
                for role in realm_roles:
                    if role["name"] == _role:
                        isExist = True
                        break
                if not isExist:
                    createRealmRole(_role, "Org admin created role")
            createGroupWithRoles(admin_data["org"], requiredRoleName, requiredRoles)
            return {"message": "created role"}
        else :
            createRealmRole(requiredRoleName, "Org admin created role")
            return {"message": "created role"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/orgs/roles/users")
async def assign_role_or_rolegroup_to_user(request: Request):
    required_roles = ["org_admin"]

    try:
        admin_data = decodeUserToken(request.headers.get('Authorization').split()[1])
        if not checkRoles(admin_data["roles"], required_roles):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )

        request_data = await request.json()
        requiredRoleGroup = request_data["role"]
        requiredUser = request_data["email"]
        if not checkUserOrg(requiredUser, admin_data["org"]):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )
        org_roles = getOrgRoles(admin_data["org"])
        for org_role in org_roles:
            if org_role["name"] == requiredRoleGroup:
                addUserToGroup(requiredRoleGroup, requiredUser)
                return {"message": "assigned role to user"}
        zeron_role_groups = getOrgRoles("zeron")
        for zeron_role_group in zeron_role_groups:
            if zeron_role_group["name"] == requiredRoleGroup:
                addUserToGroup(requiredRoleGroup, requiredUser)
                return {"message": "assigned role to user"}
        updateUserRole(requiredUser, requiredRoleGroup)
        return {"message": "assigned role to user"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/orgs/roles")
async def get_org_roles(request: Request):
    required_roles = ["org_admin"]

    required_attributes = [{ 'role': 'org_admin', 'attributes': { 'view': 'custom_roles' }}]

    try:
        admin_data = decodeUserToken(request.headers.get('Authorization').split()[1])
        if not checkRoles(admin_data["roles"], required_roles):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )
        hasAccess = False
        for requirements in required_attributes:
            if checkRoleAttribute(requirements["role"], requirements["attributes"]):
                hasAccess = True
                break
        if not hasAccess:
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )

        org_roles = getOrgRoles(admin_data["org"])
        org_names = []
        for org_role in org_roles:
            org_names.append(org_role["name"])
        return {"roles": org_names}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))