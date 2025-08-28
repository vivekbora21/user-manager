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
from database import database

# JWT Configuration
SECRET_KEY = "your-secret-key-here"  
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Database connection
def database():
    conn = pymysql.connect(
        host="localhost",
        user="root",
        password="1234",
        database="testdb",
        port=3306,
        connect_timeout=5,
        cursorclass=pymysql.cursors.DictCursor
    )
    return conn

# Pydantic models
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

# Utility functions
def verify_password(plain_password, stored_password):
    """Verify password, handling both plain text (legacy) and bcrypt hashes"""
    if stored_password.startswith('$2b$') or stored_password.startswith('$2a$'):
        return pwd_context.verify(plain_password, stored_password)
    else:
        # Legacy plain text password
        return plain_password == stored_password

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_email(email: str):
    try:
        conn = database()
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
            user = cursor.fetchone()
            return user
    except Exception as e:
        print("ERROR getting user:", e)
        return None
    finally:
        try:
            conn.close()
        except:
            pass

def authenticate_user(email: str, password: str):
    user = get_user_by_email(email)
    if not user:
        return False
    if not verify_password(password, user['password']):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(request: Request):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Get token from cookie
    token = request.cookies.get("access_token")
    if not token or not token.startswith("Bearer "):
        raise credentials_exception
    
    token = token[7:]  # Remove "Bearer " prefix
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_email(email=email)
    if user is None:
        raise credentials_exception
    return user

# Routes
@app.get("/", response_class=HTMLResponse)
def get_login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/signup", response_class=HTMLResponse)
def get_signup(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.post("/signup")
def post_signup(fullname: str = Form(...), email: str = Form(...), password: str = Form(...)):
    try:
        hashed_password = get_password_hash(password)
        conn = database()
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (fullname, email, password) VALUES (%s, %s, %s)",
                (fullname, email, hashed_password)
            )
        conn.commit()
        return RedirectResponse("/", status_code=303)
    except Exception as e:
        print("ERROR in signup:", e)
        return HTMLResponse("<h3>Error creating account. <a href='/signup'>Try again</a></h3>", status_code=400)
    finally:
        try:
            conn.close()
        except:
            pass

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/login")
async def post_login(request: Request, email: str = Form(...), password: str = Form(...)):
    user = authenticate_user(email, password)
    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid email or password"
        })
    
    # Upgrade legacy passwords to bcrypt
    if not user['password'].startswith('$2'):
        try:
            hashed_password = get_password_hash(password)
            conn = database()
            with conn.cursor() as cursor:
                cursor.execute(
                    "UPDATE users SET password=%s WHERE email=%s",
                    (hashed_password, email)
                )
            conn.commit()
            conn.close()
        except Exception as e:
            print("ERROR upgrading password:", e)
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user['email']}, expires_delta=access_token_expires
    )
    
    response = RedirectResponse("/home", status_code=303)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    return response

@app.get("/home", response_class=HTMLResponse)
async def get_home(request: Request):
    try:
        current_user = await get_current_user(request)
        return templates.TemplateResponse("home.html", {
            "request": request,
            "user_fullname": current_user['fullname']
        })
    except HTTPException:
        return RedirectResponse("/", status_code=303)

# Protected API endpoints
@app.get("/api/users")
async def get_users(request: Request):
    try:
        conn = database()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, fullname, email FROM users")
            users = cursor.fetchall()
        return JSONResponse(content=users)
    except HTTPException:
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    except Exception as e:
        print("ERROR in get_users:", e)
        return JSONResponse(content={"error": "Server error"}, status_code=500)
    finally:
        try:
            conn.close()
        except:
            pass

@app.get("/api/users/{user_id}")
async def get_user(user_id: int, request: Request):
    try:
        conn = database()
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, fullname, email FROM users WHERE id=%s", (user_id,))
            row = cursor.fetchone()
        if row:
            return JSONResponse(content=row)
        return JSONResponse(content={"error": "User not found"}, status_code=404)
    except HTTPException:
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    except Exception as e:
        print("ERROR getting user:", e)
        return JSONResponse(content={"error": "Server error"}, status_code=500)

@app.put("/api/users/{user_id}")
async def update_user(
    request: Request,
    user_id: int,
    fullname: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    try:
        hashed_password = get_password_hash(password)
        conn = database()
        with conn.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET fullname=%s, email=%s, password=%s WHERE id=%s",
                (fullname, email, hashed_password, user_id)
            )
            conn.commit()
            updated_rows = cursor.rowcount

        if updated_rows == 0:
            raise HTTPException(status_code=404, detail="User not found")

        return JSONResponse(content={"message": "User updated successfully"})
    except HTTPException:
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    except Exception as e:
        print("ERROR updating user:", e)
        return JSONResponse(content={"error": "Server error"}, status_code=500)

@app.delete("/api/users/{user_id}")
async def delete_user(user_id: int, request: Request):
    try:
        conn = database()
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
            conn.commit()
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")
        return {"message": "User deleted successfully"}
    except HTTPException:
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    except Exception as e:
        print("ERROR deleting user:", e)
        return JSONResponse(content={"error": "Server error"}, status_code=500)

@app.get("/update", response_class=HTMLResponse)
async def get_update(request: Request):
    try:
        return templates.TemplateResponse("update.html", {"request": request})
    except HTTPException:
        return RedirectResponse("/", status_code=303)

@app.get("/add", response_class=HTMLResponse)
async def get_add_page(request: Request):
    try:
        return templates.TemplateResponse("add.html", {"request": request})
    except HTTPException:
        return RedirectResponse("/", status_code=303)

@app.post("/api/users")
async def create_user(
    request: Request,
    fullname: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    try:
        hashed_password = get_password_hash(password)
        conn = database()
        with conn.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (fullname, email, password) VALUES (%s, %s, %s)",
                (fullname, email, hashed_password)
            )
        conn.commit()
        return RedirectResponse("/home", status_code=303)
    except HTTPException:
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)
    except Exception as e:
        print("ERROR in adding user:", e)
        return JSONResponse(content={"error": "Failed to create user"}, status_code=400)
    finally:
        try:
            conn.close()
        except:
            pass

@app.post("/logout")
async def logout():
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie("access_token")
    return response