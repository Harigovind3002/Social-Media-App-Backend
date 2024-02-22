# Importing necessary modules and classes
from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from datetime import datetime, timedelta
from typing import List
from pydantic import BaseModel
from jose import JWTError, jwt
from typing import Optional
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm.exc import NoResultFound

# Creating an instance of the FastAPI class
app = FastAPI()

DATABASE_URL = "sqlite:///./test5.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI(debug=True)

# exception handler for HTTP exceptions
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": exc.detail},
    )

# pydantic model for the token
class Token(BaseModel):
    access_token: str
    token_type: str

# pydantic model for the token data
class TokenData(BaseModel):
    username: str | None = None

# pydantic model for login credentials
class LoginCredentials(BaseModel):
    username: str
    password: str

# SQLAlchemy model for the follower relationship
class Follower(Base):
    __tablename__ = "followers"
    follower_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    followee_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
# SQLAlchemy model for the user
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    posts = relationship("Post", back_populates="owner")
    followers = relationship(
    "User",
    secondary="followers",
    primaryjoin="User.id==Follower.follower_id",
    secondaryjoin="User.id==Follower.followee_id",
    back_populates="following",
    )
    following = relationship(
        "User",
        secondary="followers",
        primaryjoin="User.id==Follower.followee_id",
        secondaryjoin="User.id==Follower.follower_id",
        back_populates="followers",
    )

# SQLAlchemy model for the post
class Post(Base):
    __tablename__ = "posts"
    id = Column(Integer, primary_key=True, index=True)
    content = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="posts")

# creating database tables
Base.metadata.create_all(bind=engine)

# pydantic models for creating and responding user data
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime
    followers: List[str] = []

    def __init__(self, user: User, **kwargs):
        super().__init__(**kwargs)
        self.id = user.id
        self.username = user.username
        self.email = user.email
        self.created_at = user.created_at
        self.followers = [follower.username for follower in user.followers]

# pydantic model for following a user
class FollowUser(BaseModel):
    followee_id: int

# pydantic model for creating a post
class PostCreate(BaseModel):
    content: str

# pydantic model for responding with post data
class PostResponse(BaseModel):
    id: int
    content: str
    created_at: datetime
    owner: UserResponse

# function to get a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# FastAPI route to create a new user
@app.post("/users/", response_model=UserResponse)
def create_user(
    user: UserCreate, 
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Creating a new user in the database
    db_user = User(username=user.username, email=user.email, password=user.password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

# FastAPI route to generate an access token for authentication
@app.post("/token", response_model=dict)
def login_for_access_token(db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
) -> Token:
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not user.password == form_data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Generating an access token for the user
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    Token(access_token=access_token, token_type="bearer")
    return {
        "message": "Successfully logged in",
        "access_token": access_token,
        "token_type": "bearer"
    }
    
# function to get the current authenticated user
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials = decode_token(token)
    user_id : str = credentials.get("sub")
    user = db.query(User).filter(User.username == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=user_id)
    return user

# Function to decode the JWT token
def decode_token(token: str, credentials_exception: HTTPException = Depends(HTTPException)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise credentials_exception

# Function to create an access token
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# FastAPI route to list all users
@app.get("/users/", response_model=List[UserResponse])
def list_users(
    skip: int = Query(0, alias="page"),
    limit: int = Query(10, alias="size"),
    db: Session = Depends(get_db)
):
    # recieves a paginated list of users from the database
    users = db.query(User).offset(skip).limit(limit).all()
    users_response = [
        UserResponse(
            user,
            id=user.id,
            username=user.username,
            email=user.email,
            created_at=user.created_at,
            followers=[follower.username for follower in user.followers],
        )
        for user in users
    ]
    return users_response

# FastAPI route to list all posts
@app.get("/posts/", response_model=List[PostResponse])
def list_posts(
    skip: int = Query(0, alias="page"),
    limit: int = Query(10, alias="size"),
    db: Session = Depends(get_db)
):
    posts = db.query(Post).order_by(Post.created_at.desc()).offset(skip).limit(limit).all()
    return posts

# FastAPI route to follow a user
@app.post("/users/{user_id}/follow", response_model=UserResponse)
def follow_user(
    username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # checking whether follower is exisiting or not
    followee = db.query(User).filter(User.username == username).first()
    if not followee:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    # checking whether the user is trying to follow themselves
    if followee == current_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot follow yourself")
    print("Current User ID:", current_user.id)
    print("Followee ID:", followee.id)
    
    # checking whether there exist a relatiobship between user and follower
    try:
        existing_relationship = (
            db.query(Follower)
            .filter_by(follower_id=current_user.id, followee_id=followee.id)
            .one()
        )
        print("Existing Relationship Found:", existing_relationship)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Already following this user")
    except NoResultFound:
        existing_relationship = None
        print("No Existing Relationship Found")
        
    # adding the follower to the current user's followers
    followee.followers.append(current_user)
    db.commit()
    followers_usernames = [follower.username for follower in current_user.followers]
    followers_usernames = [follower.username for follower in followee.followers]
    user_response = UserResponse(
        followee,
        id=followee.id,
        username=followee.username,
        email=followee.email,
        created_at=followee.created_at,
        followers=followers_usernames,
    )
    return user_response

# FastAPI route to unfollow a user
@app.post("/users/{user_id}/unfollow", response_model=UserResponse)
def unfollow_user(
    target_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    followee = db.query(User).filter(User.username == target_username).first()
    if not followee:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    # checing whether the current user is following the specified user
    if current_user in followee.followers:
        # removing the followers from the user's followers
        followee.followers.remove(current_user)
        db.commit()
        db.refresh(followee)
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{current_user.username} is not following {target_username}")

    followers_usernames = [follower.username for follower in followee.followers]
    user_response = UserResponse(
        followee,
        id=followee.id,
        username=followee.username,
        email=followee.email,
        created_at=followee.created_at,
        followers=followers_usernames,
    )
    return user_response
# FastAPI route to create a new post
@app.post("/posts/", response_model=PostResponse)
def create_post(
    post: PostCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_post = Post(content=post.content, owner_id=current_user.id)
    db.add(db_post)
    db.commit()
    db.refresh(db_post)
    return db_post

# FastAPI route to get all posts ordered chronologically
@app.get("/posts/", response_model=List[PostResponse])
def get_posts(
    skip: int = Query(0, alias="page"),
    limit: int = Query(10, alias="size"),
    db: Session = Depends(get_db)
):
    posts = db.query(Post).order_by(Post.created_at.desc()).offset(skip).limit(limit).all()
    return posts

# FastAPI route to delete a post
@app.delete("/posts/{post_id}", response_model=dict)
def delete_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # checking whether the post exists
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")
    # check whether the current user is the owner of the post
    if post.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not the owner of this post")
    # deleting the post from the database
    db.delete(post)
    db.commit()
    return {"message": "Post deleted successfully"}

# FastAPI route to update a post
@app.put("/posts/{post_id}", response_model=PostResponse)
def update_post(
    post_id: int,
    updated_post: PostCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    post = db.query(Post).filter(Post.id == post_id).first()
    if not post:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Post not found")
    if post.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You are not the owner of this post")

    post.content = updated_post.content
    db.commit()
    db.refresh(post)
    return post

# FastAPI route to delete a user
@app.delete("/users/me", response_model=dict)
def delete_user(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.delete(current_user)
    db.commit()
    return {"message": "User deleted successfully"}
