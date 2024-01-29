from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from services.keycloak import getMasterAccessToken, createRealmUserWithRoles, decodeUserToken, checkRoles, getRealmRoles, createRealmRole, createGroupWithRoles, addUserToGroup, getOrgRoles, checkRoleAttribute
from fastapi.middleware.cors import CORSMiddleware

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
    return {"message": "Compliance Service"}

@app.get("/compliance")
async def view_compliance(request: Request):
    required_roles = ["Compliance"]

    try:
        admin_data = decodeUserToken(request.headers.get('Authorization').split()[1])
        if not checkRoles(admin_data["roles"], required_roles):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )

        return {"message": "access to compliance"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/admin/compliance")
async def view_compliance(request: Request):
    required_roles = ["org_admin"]

    try:
        admin_data = decodeUserToken(request.headers.get('Authorization').split()[1])
        if not checkRoles(admin_data["roles"], required_roles):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )

        return {"message": "admin access to compliance"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))