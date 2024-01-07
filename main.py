#building RestApi using FastAPI , this project to make to datasets (users and candidates) using mangoDB , then to make the users be able to add , remove , update and view
#the candidates , and using authentication verifier so that no everyone can edit .

#some libraries needed :
from fastapi import FastAPI, status, HTTPException, Depends
from pydantic import BaseModel, Field, EmailStr,ValidationError
from pydantic_settings import BaseSettings
from bson import ObjectId
from typing import List, Optional
from pymongo import MongoClient
from fastapi import APIRouter
from fastapi.security import OAuth2PasswordBearer , OAuth2PasswordRequestForm
import time
from datetime import timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from motor.motor_asyncio import AsyncIOMotorClient
import motor.motor_asyncio
from passlib.context import CryptContext
import logging

# Add this line at the beginning of your script
logging.basicConfig(level=logging.DEBUG)


# Define an API router
router = APIRouter()

# Placeholder for MongoDB client and database
client= None
db= None

SECRET_KEY = "your-secret-key"  # Replace with a strong secret key
ALGORITHM = "HS256"  # Algorithm for signing the token
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Adjust expiration time as needed

# TokenData model for JWT token
class TokenData(BaseModel):
    username: Optional[str] = None

# Function to create an access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = time.time() + expires_delta.seconds
    else:
        expire = time.time() + ACCESS_TOKEN_EXPIRE_MINUTES * 60
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Settings model for configuration
class Settings(BaseSettings):
    SECRET_KEY: str = "1234"  # Replace with your actual secret key
    ALGORITHM: str = "HS256"  # Replace with your chosen algorithm
    openai_api_key: str = "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"

    class Config:
        env_file = ".env"  # Path to your environment file (optional)

# Initialize settings
settings = Settings()

# User and Candidate models
class User(BaseModel):
    id: ObjectId = Field(default_factory=ObjectId, alias="_id")
    first_name: str
    last_name: str
    email: EmailStr
    username: str
    hashed_password: str

    class Config:
        arbitrary_types_allowed = True

class UserCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    username: str
    password: str


class Candidate(BaseModel):
    id: ObjectId = Field(default_factory=ObjectId, alias="_id")
    first_name: str
    last_name: str
    email: EmailStr
    career_level: Optional[str]
    job_major: Optional[str]
    years_of_experience: int
    degree_type: Optional[str] = None
    skills: List[str]
    nationality: str
    city: str
    salary: int
    gender: str = Field(..., min_length=1, max_length=15)
    class Config:
        arbitrary_types_allowed = True


# Password hashing and authentication setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")  # Define authentication scheme
# Function to hash password
def hash_password(password: str):
    return pwd_context.hash(password)

# Connect to MongoDB
async def get_database():
    client = motor.motor_asyncio.AsyncIOMotorClient("mongodb://127.0.0.1:27017/?directConnection=true&serverSelectionTimeoutMS=2000")
    return client["data"]

# Dependency for database connection
async def get_db():
    db = await get_database()
    return db

# Placeholder for user retrieval from database

async def get_user(username: str):
    # Use the global MongoClient or create a new one if not created
    global client
    if client is None:
        client = AsyncIOMotorClient("mongodb://127.0.0.1:27017/?directConnection=true&serverSelectionTimeoutMS=2000")
    db = client["data"]
    users_collection = db["users"]

    # Retrieve the user from the database based on the username
    user_data = await users_collection.find_one({"username": username})

    # If user is not found, raise HTTPException with 404 status code
    if user_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with username {username} not found",
        )

    # Create a User instance from the retrieved data
    user = User(**user_data)
    return user

# FastAPI application instance
app = FastAPI()

# Login endpoint
@app.post("/token")

async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await get_user(form_data.username)
    if not user or not pwd_context.verify(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})  # Generate token
    return {"access_token": access_token, "token_type": "bearer"}

# Connect to MongoDB
client = motor.motor_asyncio.AsyncIOMotorClient("mongodb://127.0.0.1:27017/?directConnection=true&serverSelectionTimeoutMS=2000")
db = client["data"]
users_collection = db["users"]
candidates_collection = db["candidates"]


# Dependency for authentication
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok"}

# # User management endpoint (placeholder for now) 
.................................problem in the code here..................................
# @app.post("/users/", response_model=User)
# async def create_user(user: UserCreate):
#     try:
#         # Check if username or email already exists
#         existing_user = users_collection.find_one(
#             {"$or": [{"username": user.username}, {"email": user.email}]}
#         )
#         if existing_user:
#             raise HTTPException(status_code=400, detail="Username or email already exists")
#
#         # Insert the new user into the database
#         user_dict = user.dict()
#         user_dict["hashed_password"] = "hash_function_here"  # Replace with your password hashing logic
#         user_id = users_collection.insert_one(user_dict).inserted_id
#         created_user = users_collection.find_one({"_id": user_id})
#
#         return User(**created_user)
#
#
#     except Exception as e:
#         logging.error(f"An error occurred: {e}")
#         raise HTTPException(status_code=500, detail="Internal Server Error")

# Placeholder for candidate retrieval logic
@app.get("/candidate/{candidate_id}")
async def get_candidate(
    candidate_id: str,
    current_user: User = Depends(get_current_user)
):
    # Retrieve the candidate from the database based on the candidate_id
    candidate_data = await candidates_collection.find_one({"_id": ObjectId(candidate_id)})

    # If candidate is not found, raise HTTPException with 404 status code
    if candidate_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Candidate with id {candidate_id} not found",
        )

    # Return the retrieved candidate
    return candidate_data

# # Candidate CRUD endpoints (placeholders for now)
# @app.post("/candidate")
# async def create_candidate(candidate: Candidate, current_user: User = Depends(get_current_user)):
#     # Only authenticated users are allowed to create candidates
#
#     # Example: Store the candidate in the database
#     result = await candidates_collection.insert_one(candidate.dict())
#
#     # Return the created candidate or a confirmation message
#     created_candidate = await candidates_collection.find_one({"_id": result.inserted_id})
#     return created_candidate

# # Placeholder for candidate retrieval logic
# @app.get("/candidate/{candidate_id}")
# async def get_candidate(candidate_id: str, current_user: User = Depends(get_current_user)):
#     # Only authenticated users are allowed to view candidates
#
#     # Retrieve the candidate from the database based on the candidate_id
#     candidate_data = await candidates_collection.find_one({"_id": ObjectId(candidate_id)})
#
#     # If candidate is not found, raise HTTPException with 404 status code
#     if candidate_data is None:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail=f"Candidate with id {candidate_id} not found",
#         )
#
#     # Return the retrieved candidate
#     return candidate_data
#
# # Placeholder for candidate update logic
# @app.put("/candidate/{candidate_id}")
# async def update_candidate(candidate_id: str, updated_candidate: Candidate, current_user: User = Depends(get_current_user)):
#     # Only authenticated users are allowed to update candidates
#
#     # Placeholder example: Validate updated candidate data and update in the database
#     # You might want to add more validation and data processing based on your requirements
#
#     # Example: Update the candidate in the database
#     result = await candidates_collection.update_one(
#         {"_id": ObjectId(candidate_id)},
#         {"$set": updated_candidate.dict()}
#     )
#
#     # Check if the candidate was updated successfully
#     if result.modified_count == 0:
#         raise HTTPException(
#             status_code=status.HTTP_404_NOT_FOUND,
#             detail=f"Candidate with id {candidate_id} not found",
#         )
#
#     # Return a confirmation message
#     return {"message": "Candidate updated successfully"}

# Placeholder for candidate deletion logic
@app.delete("/candidates/{candidate_id}")
async def delete_candidate(candidate_id: str, current_user: User = Depends(get_current_user)):
    # Only authenticated users are allowed to delete candidates

    # Delete the candidate from the database
    result = await candidates_collection.delete_one({"_id": ObjectId(candidate_id)})

    # Check if the candidate was deleted successfully
    if result.deleted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Candidate with id {candidate_id} not found",
        )

    # Return a confirmation message
    return {"message": "Candidate deleted successfully"}

# All candidates search endpoint (placeholder for now)
@app.get("/all-candidates")
async def get_all_candidates():
    # Retrieve all candidates from the database
    all_candidates = await candidates_collection.find().to_list(length=None)

    # Return the list of candidates
    return all_candidates

# Report generation endpoint (placeholder for now)
@app.get("/generate-report")
async def generate_report(current_user: User = Depends(get_current_user)):
    # Implement report generation logic here

    # Placeholder example: Query the database for user-related information
    user_data = await users_collection.find().to_list(length=None)

    # Format the information into a simple report
    report_content = f"Report for User {current_user.username}:\n"
    for user in user_data:
        report_content += f"- User ID: {user['_id']}, Username: {user['username']}, Email: {user['email']}\n"

    # Return the report content
    return {"report": report_content}

#-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
# Create sample users and candidates
user1 = User(
    first_name="John",
    last_name="Doe",
    email="johndoe@example.com",
    hashed_password="password123",
    username = "John"
)

user2 = User(
    first_name="Jane",
    last_name="Smith",
    email="janesmith@example.com",
    hashed_password="password456",
    username = "Jane"
)

# Create two candidates
candidate1 = Candidate(
    first_name="Alice",
    last_name="Wonderland",
    email="alice@example.com",
    career_level="Mid-Senior Level",
    job_major="Software Engineering",
    years_of_experience=5,
    degree_type="Master's",
    skills=["Python", "Java", "React"],
    nationality="American",
    city="New York",
    salary=120000,
    gender="Female"
)

candidate2 = Candidate(
    first_name="Bob",
    last_name="Builder",
    email="bob@example.com",
    career_level="Entry Level",
    job_major="Construction Management",
    years_of_experience=1,
    skills=["Project Management", "Building Design", "CAD"],
    nationality="Canadian",
    city="Toronto",
    salary=60000,
    gender="Male",
    degree_type="Bachelor's"
)



