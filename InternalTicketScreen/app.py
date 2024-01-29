from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from services.keycloak import getMasterAccessToken, createRealmUserWithRoles, decodeUserToken, checkRoles, getRealmRoles, createRealmRole, createGroupWithRoles, addUserToGroup, getOrgRoles, checkRoleAttribute, checkUserAttributes
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
    return {"message": "Internal Ticket Screen Service"}

@app.get("/internalTicketScreen")
async def view_internalTicketScreen(request: Request):
    required_roles = ["InternalTicketScreen"]

    try:
        admin_data = decodeUserToken(request.headers.get('Authorization').split()[1])
        if not checkRoles(admin_data["roles"], required_roles):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )

        return {"message": "access to internalTicketScreen"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/internalTicketScreen/lob")
async def view_internalTicketScreen(request: Request):
    required_roles = ["InternalTicketScreen"]
    required_lob_attribute = {"lob-analysis": "Pune"}

    try:
        admin_data = decodeUserToken(request.headers.get('Authorization').split()[1])
        if not checkRoles(admin_data["roles"], required_roles):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )

        if not checkUserAttributes(admin_data["email"], required_lob_attribute):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )

        return {"message": "access to internalTicketScreen lob"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/admin/internalTicketScreen")
async def view_internalTicketScreen(request: Request):
    required_roles = ["org_admin"]

    try:
        admin_data = decodeUserToken(request.headers.get('Authorization').split()[1])
        if not checkRoles(admin_data["roles"], required_roles):
            return JSONResponse(
                status_code=401,
                content={"message": "You do not have permission to access this resource"},
            )

        return {"message": "admin access to internalTicketScreen"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))