from fastapi import FastAPI, Depends, Header, Request, Response
from typing import Annotated
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.exceptions import HTTPException

#validar la librería JWT python-jose vs pyjwt
from jose import jwt

app = FastAPI()
#esta dependencia creará un token, pero debemos indicarle dónde debe crearlo
oauth2_schema = OAuth2PasswordBearer(tokenUrl="token")

users ={
    "user1": {"username":"pablo", "email":"pablo@gmail.com", "password":"fakepass"},
    "user2": {"username":"juan", "email":"juan@gmail.com", "password":"user2"}
}

# "my-secret" podría ser tomado desde la base de datos
def encode_token(payload: dict) -> str:
    token = jwt.encode(payload, "my-secret", algorithm="HS256")
    return token

# Se pasa el parametro como header
def decode_token(token: Annotated[str, Depends(oauth2_schema)]) -> dict:
    data = jwt.decode(token, "my-secret", algorithms=["HS256"])
    user = users.get(data["username"])
    return user

@app.post("/token")
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    print (form_data.username)
    user = users.get(form_data.username)
    if not user or form_data.password != user["password"]:
        raise HTTPException (status_code=400, detail="Incorrect Username or password")
    token = encode_token({"username":user["username"], "email": user["email"]})

    return {"access_token":token}


## Ruta protegida en la aplicación
@app.get("/users/profile")
def profile(my_user: Annotated[dict, Depends(decode_token)]):
    return my_user


## Headers params
@app.get("/dashboard")
def dashboard(access_token: Annotated[str, Header()]):
    return ""


def get_headers(
            access_token: Annotated[str | None, Header()] = None, 
    user_role: Annotated[list[str] | None, Header()] = None):
    if access_token != "secret-token":
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"access_token": access_token, "user_role": user_role}


## Que sea opcional
## Headers params

@app.get("/dashboards")
def dashboard(
    headers: Annotated[dict, Depends(get_headers)],
    request: Request,
    response: Response):

    # Desde el servidor se puede enviar headers de acuerdo al contexto 
    response.headers["user_status"] = "enabled"
    print (request.headers)

    # Se retornan desde 
    return {"access_token": headers["access_token"], "user_rone": headers["user_role"]}

