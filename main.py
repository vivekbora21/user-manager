from fastapi import FastAPI, Form, HTTPException, Request, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from datetime import datetime, timedelta
import pymysql
from typing import Optional
from passkey import PassKey

# CONFIG

SECRET_KEY = PassKey.SECRET_KEY 
ALGORITHM = PassKey.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = PassKey.ACCESS_TOKEN_EXPIRE_MINUTES

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# DATABASE
def database():
    return pymysql.connect(
        host="localhost",
        user="root",
        password="1234",
        database="testdb",
        port=3306,
        connect_timeout=5,
        cursorclass=pymysql.cursors.DictCursor
    )


# Pydantic Models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

# Utility Functions
def verify_password(plain_password, stored_password):
    if stored_password.startswith('$2b$') or stored_password.startswith('$2a$'):
        return pwd_context.verify(plain_password, stored_password)
    return plain_password == stored_password  # legacy

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_email(email: str):
    conn = database()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            return cursor.fetchone()
    finally:
        conn.close()

def authenticate_user(email: str, password: str):
    user = get_user_by_email(email)
    if not user or not verify_password(password, user['password']):
        return None
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Jinja Helper
def render_template(name: str, request: Request, **context):
    """Wrapper to simplify template rendering with request always included"""
    return templates.TemplateResponse(name, {"request": request, **context})

# Current User Dependency
async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token or not token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(token[7:], SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = get_user_by_email(email=email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# ROUTES
@app.get("/", response_class=HTMLResponse)
def get_login(request: Request):
    return render_template("login.html", request)

@app.get("/signup", response_class=HTMLResponse)
def get_signup(request: Request):
    return render_template("signup.html", request)

@app.post("/signup")
def post_signup(fullname: str = Form(...), email: str = Form(...), password: str = Form(...)):
    try:
        hashed_password = get_password_hash(password)
        conn = database()
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO users (fullname, email, password) VALUES (%s, %s, %s)", (fullname, email, hashed_password))
        conn.commit()
        return RedirectResponse("/", status_code=303)
    finally:
        conn.close()

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    token = create_access_token(data={"sub": user['email']}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}

@app.post("/login")
async def post_login(request: Request, email: str = Form(...), password: str = Form(...)):
    user = authenticate_user(email, password)
    if not user:
        return render_template("login.html", request, error="Invalid email or password")

    token = create_access_token(data={"sub": user['email']}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    response = RedirectResponse("/home", status_code=303)
    response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True,
                        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                        expires=ACCESS_TOKEN_EXPIRE_MINUTES * 60 )
    return response

@app.get("/home", response_class=HTMLResponse)
async def get_home(request: Request):
    try:
        current_user = await get_current_user(request)
        return render_template("home.html", request, user_fullname=current_user['fullname'])
    except HTTPException:
        return RedirectResponse("/", status_code=303)

@app.get("/update", response_class=HTMLResponse)
async def get_update(request: Request):
    return render_template("update.html", request)

@app.get("/add", response_class=HTMLResponse)
async def get_add_page(request: Request):
    return render_template("add.html", request)

@app.post("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("access_token")
    return response

# API Endpoints
@app.get("/api/users")
async def get_users():
    conn = database()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, fullname, email FROM users")
            return cursor.fetchall()
    finally:
        conn.close()

@app.get("/api/users/{user_id}")
async def get_user(user_id: int):
    conn = database()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, fullname, email FROM users WHERE id=%s", (user_id,))
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            return row
    finally:
        conn.close()

@app.post("/api/users")
async def create_user(fullname: str = Form(...), email: str = Form(...), password: str = Form(...)):
    conn = database()
    try:
        hashed_password = get_password_hash(password)
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO users (fullname, email, password) VALUES (%s, %s, %s)", (fullname, email, hashed_password))
        conn.commit()
        return RedirectResponse("/home", status_code=303)
    finally:
        conn.close()

@app.put("/api/users/{user_id}")
async def update_user(user_id: int, fullname: str = Form(...), email: str = Form(...), password: str = Form(...)):
    conn = database()
    try:
        hashed_password = get_password_hash(password)
        with conn.cursor() as cursor:
            cursor.execute("UPDATE users SET fullname=%s, email=%s, password=%s WHERE id=%s", (fullname, email, hashed_password, user_id))
            conn.commit()
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")
        return {"message": "User updated successfully"}
    finally:
        conn.close()

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int):
    conn = database()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
            conn.commit()
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")
        return {"message": "User deleted successfully"}
    finally:
        conn.close()