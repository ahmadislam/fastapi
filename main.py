from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from datetime import datetime, timedelta
import redis
from fastapi.responses import FileResponse
import os
from jose import JWTError, jwt
from typing import Optional

app = FastAPI()

# Secret key for JWT (use a more secure key in production)
SECRET_KEY = "secretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Redis setup
redis_client = redis.StrictRedis(host='redis', port=6379, db=0)

# OAuth2 setup
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Mock database
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "full_name": "Test User",
        "email": "testuser@example.com",
        "hashed_password": "helloai",
        "disabled": False,
    }
}

# User and Task Models
class User(BaseModel):
    username: str
    email: str
    full_name: str
    disabled: bool = None

class Task(BaseModel):
    task_name: str
    created_at: Optional[datetime] = None

class UserInDB(User):
    hashed_password: str

# Authentication and Authorization Functions
def fake_hash_password(password: str):
    return password

def verify_password(plain_password, hashed_password):
    return fake_hash_password(plain_password) == hashed_password

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
        user = fake_users_db.get(username)
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# API Endpoints
@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user['hashed_password']):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user['username']})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/tasks/")
async def create_task(task: Task, current_user: User = Depends(get_current_user)):
    """
    Create a new task for the current user. Requires authentication.
    """
    task.created_at = task.created_at or datetime.utcnow()  # Set to current time if not provided
    redis_client.rpush(f"tasks:{current_user['username']}", task.json())
    return task

@app.get("/tasks/")
async def get_tasks(current_user: User = Depends(get_current_user)):
    """
    Retrieve all tasks for the current user. Requires authentication.
    """
    tasks = redis_client.lrange(f"tasks:{current_user['username']}", 0, -1)
    return [Task.parse_raw(task) for task in tasks]

@app.post("/template/")
async def fill_template(template: dict, current_user: User = Depends(get_current_user)):
    """
    Fill a template for the current user. Requires authentication.
    """
    return {"message": "Template filled", "data": template}

@app.get("/")
async def read_root():
    return {"message": "Welcome to the FastAPI application!"}

@app.get("/favicon.ico")
async def favicon():
    return FileResponse(os.path.join(os.getcwd(), "favicon.ico"))
