from lexio.accounts import create_team, create_user, assign_member_to_team
from lexio.accounts.models import User
from db import SessionLocal, engine

from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param

from pydantic import BaseModel
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from passlib.hash import pbkdf2_sha256
from typing import Optional
import jwt
import time


def get_db():
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()


app = FastAPI()

origins = [
    "http://localhost",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def read_root():
    return {"Hello": "World"}


class Registration(BaseModel):
    username: str
    email: str
    password: str
    password_confirmation: str
    team_name: str

from lexio.accounts import TeamCreate, UserCreate

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

class Authentication(BaseModel):
    email: str
    password: str

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str = None

def create_access_token(*, data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM).decode('utf-8')
    return encoded_jwt


class Auth(SecurityBase):
    def __init__(self, scheme_name: str = None, auto_error: bool = True):
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization:
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_403_FORBIDDEN, detail="Not authenticated"
                )
            else:
                return None
        return param

auth = Auth(auto_error=False)

def get_current_user(token):
    if not token:
        return None
    decoded_jwt = jwt.decode(token, SECRET_KEY, algorithm=ALGORITHM)
    username = decoded_jwt.get('sub')
    return username

@app.get('/teams')
def teams(db: Session = Depends(get_db), auth: Auth = Depends(auth)):
    username = get_current_user(auth)
    if not username:
        response = Response(headers={"WWW-Authenticate": "Basic"}, status_code=401)
        return response
    decoded_jwt = jwt.decode(auth, SECRET_KEY, algorithm=ALGORITHM)
    username = decoded_jwt.get('sub')
    user = db.query(User) \
        .filter(User.username == username) \
        .one()
    teams = user.teams
    return {'teams': teams}



@app.post('/authenticate')
def authenticate(authentication: Authentication, response: Response, db: Session = Depends(get_db)):
    auth_dict = authentication.dict()
    email = auth_dict.get('email')
    password = auth_dict.get('password')

    user = db.query(User) \
        .filter(User.email == email) \
        .one()

    if not user:
        raise HTTPException(status_code=400, detail="User could not be found.")
    if not pbkdf2_sha256.verify(password, user.password_hash):
        raise HTTPException(status_code=400, detail="Password did not match.")

    access_token_expires = timedelta(minutes=1800)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    content = {"message": "Come to the dark side, we have cookies"}

    response = JSONResponse(content=content)
    cookie = f'Basic: {access_token}'
    response.set_cookie(
        "Authorization",
        value=cookie,
        httponly=True,
        max_age=1800,
        expires=1800,
    )

    return response

@app.post("/register")
def register(registration: Registration, db: Session = Depends(get_db)):
    registration_dict = registration.dict()
    email = registration_dict.get('email')
    username = registration_dict.get('username')
    password = registration_dict.get('password')
    password_confirmation = registration_dict.get('password_confirmation')
    team_name = registration_dict.get('team_name')

    user_exists = db.query(User) \
        .filter(User.email == email) \
        .count() > 0

    username_exists = db.query(User) \
        .filter(User.username == username) \
        .count() > 0


    if user_exists or username_exists:
        raise HTTPException(status_code=400, detail="User could not be created.")
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Passwords should be more than 8 characters.")


    if password != password_confirmation:
        raise HTTPException(status_code=400, detail="Passwords do not match.")

    # Turn this into transaction
    try:
        team = create_team(db=db, team=TeamCreate(name=team_name))
        user = create_user(db=db, user=UserCreate(email=email, password=password, username=username))
        assign_member_to_team(user.id, team.id, db=db)
    except SQLAlchemyError:
        raise HTTPException(status_code=400, detail="New account creation failed")

    return registration
