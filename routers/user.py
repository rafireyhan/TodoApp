from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, Field
from models import Users
from database import SessionLocal
from typing import Annotated
from sqlalchemy.orm import Session
from starlette import status
from .auth import get_current_user
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer

router = APIRouter(
    prefix='/user',
    tags=['user']
)

bcyrpt_contect = CryptContext(schemes=['bcrypt'],deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

#JWT
SECRET_KEY = '862afcfb673dbf3a82efa5dac241594dbb731741974c20c5f7ce017c9af82634'
ALGORITHM = 'HS256'

#DATABASE CONFIGURATION
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]

#CLASS MODEL REQUEST
class UserRequest(BaseModel):
    password: str
    new_password: str = Field(min_length=6)

class PhoneRequest(BaseModel):
    phone_number: str

@router.get("/", status_code=status.HTTP_200_OK)
async def get_user(user: user_dependency,db: db_dependency):
    
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    
    return db.query(Users).filter(Users.id == user.get('id')).first()

@router.put("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(user: user_dependency,db: db_dependency, 
                      user_request: UserRequest):
    
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')

    user_model = db.query(Users).filter(Users.id == user.get('id')).first()

    if not bcyrpt_contect.verify(user_request.password, user_model.hashed_password):
        raise HTTPException(status_code=401, detail='Error on password change')

    user_model.hashed_password = bcyrpt_contect.hash(user_request.new_password)

    db.add(user_model)
    db.commit()

@router.put("/phone_number", status_code=status.HTTP_204_NO_CONTENT)
async def change_phone_number(user: user_dependency,db: db_dependency,
                              phone_request: PhoneRequest):
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    
    user_model = db.query(Users).filter(Users.id == user.get('id')).first()

    user_model.phone_number = phone_request.phone_number

    db.add(user_model)
    db.commit()