import os
import httpx
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import uuid
from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field
from passlib.context import CryptContext
import jwt
from contextlib import asynccontextmanager
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.jobstores.memory import MemoryJobStore
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "weather_alerts")
JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-change-this")
JWT_ALGORITHM = "HS256"

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Database client
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# Collections
users_collection = db.users
alerts_collection = db.alerts
notifications_collection = db.notifications
admin_collection = db.admins

# Scheduler setup
scheduler = AsyncIOScheduler(jobstores={'default': MemoryJobStore()})

# NWS API Client
class NWSClient:
    def __init__(self):
        self.base_url = "https://api.weather.gov"
        self.headers = {
            "User-Agent": "WeatherAlert-App/1.0 (admin@weatheralerts.com)",
            "Accept": "application/geo+json"
        }
        self.client = httpx.AsyncClient(
            timeout=30,
            limits=httpx.Limits(max_connections=10, max_keepalive_connections=5)
        )

    async def get_active_alerts(self, state_code: str = None) -> List[Dict]:
        """Fetch active weather alerts from NWS API"""
        try:
            url = f"{self.base_url}/alerts/active"
            if state_code:
                url += f"?area={state_code}"
            
            response = await self.client.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()
            
            # Filter for critical weather events
            critical_events = [
                "tornado warning",
                "severe thunderstorm warning", 
                "blizzard warning",
                "winter storm warning",
                "high wind warning"
            ]
            
            filtered_alerts = []
            for feature in data.get("features", []):
                props = feature.get("properties", {})
                event = props.get("event", "").lower()
                
                if any(critical_event in event for critical_event in critical_events):
                    # Extract affected areas/counties
                    areas = []
                    if "geocode" in props:
                        if "UGC" in props["geocode"]:
                            areas = props["geocode"]["UGC"]
                    
                    alert_data = {
                        "id": props.get("id", str(uuid.uuid4())),
                        "event": props.get("event"),
                        "severity": props.get("severity"),
                        "urgency": props.get("urgency"),
                        "headline": props.get("headline"),
                        "description": props.get("description"),
                        "effective": props.get("effective"),
                        "expires": props.get("expires"),
                        "areas": areas,
                        "geometry": feature.get("geometry"),
                        "status": props.get("status")
                    }
                    filtered_alerts.append(alert_data)
            
            return filtered_alerts
            
        except Exception as e:
            logger.error(f"Error fetching weather alerts: {e}")
            return []

nws_client = NWSClient()

# Pydantic Models
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)

class UserLogin(BaseModel):
    username: str
    password: str

class CountySubscription(BaseModel):
    state: str = Field(..., min_length=2, max_length=2)
    counties: List[str]

class ManualNotification(BaseModel):
    message: str
    is_critical: bool = False
    target_users: Optional[List[str]] = None  # If None, send to all users

class User(BaseModel):
    id: str
    username: str
    created_at: datetime
    subscriptions: List[Dict[str, Any]] = []

class Admin(BaseModel):
    username: str
    password_hash: str

# Utility Functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user = await users_collection.find_one({"username": username}, {"_id": 0})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

async def get_current_admin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        is_admin: bool = payload.get("is_admin", False)
        
        if not is_admin or username != "adminusernamealert":
            raise HTTPException(status_code=403, detail="Admin access required")
        
        return {"username": username, "is_admin": True}
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

# US States and Counties Data
US_STATES = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California",
    "CO": "Colorado", "CT": "Connecticut", "DE": "Delaware", "FL": "Florida", "GA": "Georgia",
    "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois", "IN": "Indiana", "IA": "Iowa",
    "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine", "MD": "Maryland",
    "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi", "MO": "Missouri",
    "MT": "Montana", "NE": "Nebraska", "NV": "Nevada", "NH": "New Hampshire", "NJ": "New Jersey",
    "NM": "New Mexico", "NY": "New York", "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio",
    "OK": "Oklahoma", "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina",
    "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas", "UT": "Utah", "VT": "Vermont",
    "VA": "Virginia", "WA": "Washington", "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming"
}

# Sample counties for demo (in production, you'd load from a complete database)
SAMPLE_COUNTIES = {
    "KY": ["Jefferson", "Fayette", "Campbell", "Kenton", "Warren", "Daviess", "McCracken", "Madison", "Christian", "Oldham"],
    "IN": ["Marion", "Lake", "Allen", "Hamilton", "St. Joseph", "Vanderburgh", "Tippecanoe", "Porter", "Vigo", "Monroe"],
    "OH": ["Cuyahoga", "Franklin", "Hamilton", "Summit", "Montgomery", "Lucas", "Stark", "Butler", "Lorain", "Warren"]
}

# Weather Alert Processing
async def process_weather_alerts():
    """Background task to check for new weather alerts"""
    try:
        logger.info("Checking for weather alerts...")
        
        # Get alerts for our focus states
        all_alerts = []
        for state in ["KY", "IN", "OH"]:
            state_alerts = await nws_client.get_active_alerts(state)
            all_alerts.extend(state_alerts)
        
        # Also get nationwide alerts
        national_alerts = await nws_client.get_active_alerts()
        all_alerts.extend(national_alerts)
        
        # Remove duplicates based on alert ID
        unique_alerts = {alert["id"]: alert for alert in all_alerts}
        
        for alert_id, alert in unique_alerts.items():
            # Check if we've already processed this alert
            existing = await alerts_collection.find_one({"id": alert_id})
            if existing:
                continue
            
            # Save new alert
            alert["processed_at"] = datetime.utcnow()
            await alerts_collection.insert_one(alert)
            
            # Find affected users and send notifications
            await notify_affected_users(alert)
            
        logger.info(f"Processed {len(unique_alerts)} unique alerts")
        
    except Exception as e:
        logger.error(f"Error processing weather alerts: {e}")

async def notify_affected_users(alert: Dict):
    """Send notifications to users affected by weather alert"""
    try:
        # This is where you'd integrate with push notification service
        # For now, we'll store the notification in the database
        
        affected_users = await users_collection.find({
            "subscriptions.state": {"$exists": True}
        }).to_list(length=None)
        
        for user in affected_users:
            should_notify = False
            
            # Check if user's subscribed counties are affected
            for subscription in user.get("subscriptions", []):
                # This is simplified - in production you'd do proper geographic matching
                if subscription.get("state") in ["KY", "IN", "OH"]:  # Focus states
                    should_notify = True
                    break
            
            if should_notify:
                notification = {
                    "id": str(uuid.uuid4()),
                    "user_id": user["id"],
                    "alert_id": alert["id"],
                    "message": alert["headline"],
                    "is_critical": True,  # Weather alerts are always critical
                    "created_at": datetime.utcnow(),
                    "sent": False
                }
                await notifications_collection.insert_one(notification)
                
        logger.info(f"Created notifications for alert: {alert['event']}")
        
    except Exception as e:
        logger.error(f"Error notifying users: {e}")

# FastAPI App Setup
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Start scheduler
    scheduler.start()
    
    # Schedule weather alert checking every 5 minutes
    scheduler.add_job(
        process_weather_alerts,
        'interval',
        minutes=5,
        id='weather_alert_check',
        replace_existing=True
    )
    
    # Create admin user if not exists
    admin_exists = await admin_collection.find_one({"username": "adminusernamealert"})
    if not admin_exists:
        admin_data = {
            "username": "adminusernamealert",
            "password_hash": hash_password("adminpasswordalert"),
            "created_at": datetime.utcnow()
        }
        await admin_collection.insert_one(admin_data)
        logger.info("Created admin user")
    
    yield
    
    # Shutdown
    scheduler.shutdown()
    await client.close()

app = FastAPI(title="Weather Alert System", lifespan=lifespan)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routes

@app.get("/api/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow()}

@app.post("/api/register")
async def register_user(user_data: UserCreate):
    # Check if user exists
    existing_user = await users_collection.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Create new user
    user_id = str(uuid.uuid4())
    user = {
        "id": user_id,
        "username": user_data.username,
        "password_hash": hash_password(user_data.password),
        "created_at": datetime.utcnow(),
        "subscriptions": []
    }
    
    await users_collection.insert_one(user)
    
    # Create access token
    access_token = create_access_token(data={"sub": user_data.username})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "username": user_data.username,
            "created_at": user["created_at"]
        }
    }

@app.post("/api/login")
async def login_user(user_data: UserLogin):
    user = await users_collection.find_one({"username": user_data.username}, {"_id": 0})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token(data={"sub": user_data.username})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "created_at": user["created_at"],
            "subscriptions": user.get("subscriptions", [])
        }
    }

@app.post("/api/admin/login")
async def admin_login(admin_data: UserLogin):
    if admin_data.username != "adminusernamealert":
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    admin = await admin_collection.find_one({"username": "adminusernamealert"})
    if not admin or not verify_password(admin_data.password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    
    access_token = create_access_token(data={"sub": admin_data.username, "is_admin": True})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "admin": {"username": admin_data.username}
    }

@app.get("/api/states")
async def get_states():
    return {"states": US_STATES}

@app.get("/api/counties/{state_code}")
async def get_counties(state_code: str):
    state_code = state_code.upper()
    if state_code not in US_STATES:
        raise HTTPException(status_code=404, detail="State not found")
    
    counties = SAMPLE_COUNTIES.get(state_code, [])
    return {"state": state_code, "counties": counties}

@app.post("/api/subscribe")
async def subscribe_to_counties(
    subscription: CountySubscription,
    current_user: dict = Depends(get_current_user)
):
    # Update user's subscriptions
    await users_collection.update_one(
        {"id": current_user["id"]},
        {
            "$push": {
                "subscriptions": {
                    "id": str(uuid.uuid4()),
                    "state": subscription.state.upper(),
                    "counties": subscription.counties,
                    "created_at": datetime.utcnow()
                }
            }
        }
    )
    
    return {"message": "Successfully subscribed to weather alerts"}

@app.get("/api/my-subscriptions")
async def get_my_subscriptions(current_user: dict = Depends(get_current_user)):
    user = await users_collection.find_one({"id": current_user["id"]}, {"_id": 0})
    return {"subscriptions": user.get("subscriptions", []) if user else []}

@app.delete("/api/subscriptions/{subscription_id}")
async def delete_subscription(
    subscription_id: str,
    current_user: dict = Depends(get_current_user)
):
    await users_collection.update_one(
        {"id": current_user["id"]},
        {"$pull": {"subscriptions": {"id": subscription_id}}}
    )
    return {"message": "Subscription removed"}

@app.get("/api/alerts")
async def get_recent_alerts():
    alerts = await alerts_collection.find({}, {"_id": 0}).sort("processed_at", -1).limit(50).to_list(length=50)
    return {"alerts": alerts}

# Admin Routes
@app.get("/api/admin/users")
async def get_all_users(current_admin: dict = Depends(get_current_admin)):
    users = await users_collection.find({}, {"password_hash": 0, "_id": 0}).to_list(length=None)
    return {"users": users, "total": len(users)}

@app.post("/api/admin/notify")
async def send_manual_notification(
    notification: ManualNotification,
    current_admin: dict = Depends(get_current_admin)
):
    # Get target users
    if notification.target_users:
        users = await users_collection.find(
            {"username": {"$in": notification.target_users}}
        ).to_list(length=None)
    else:
        users = await users_collection.find({}).to_list(length=None)
    
    # Create notifications for each user
    notifications_to_insert = []
    for user in users:
        notif = {
            "id": str(uuid.uuid4()),
            "user_id": user["id"],
            "alert_id": None,  # Manual notification
            "message": notification.message,
            "is_critical": notification.is_critical,
            "created_at": datetime.utcnow(),
            "sent": False,
            "manual": True,
            "sent_by_admin": current_admin["username"]
        }
        notifications_to_insert.append(notif)
    
    if notifications_to_insert:
        await notifications_collection.insert_many(notifications_to_insert)
    
    return {
        "message": f"Notification sent to {len(users)} users",
        "is_critical": notification.is_critical
    }

@app.get("/api/admin/notifications")
async def get_admin_notifications(current_admin: dict = Depends(get_current_admin)):
    notifications = await notifications_collection.find({}, {"_id": 0}).sort("created_at", -1).limit(100).to_list(length=100)
    return {"notifications": notifications}

@app.get("/api/admin/stats")
async def get_admin_stats(current_admin: dict = Depends(get_current_admin)):
    total_users = await users_collection.count_documents({})
    total_notifications = await notifications_collection.count_documents({})
    recent_alerts = await alerts_collection.count_documents({
        "processed_at": {"$gte": datetime.utcnow() - timedelta(days=7)}
    })
    
    return {
        "total_users": total_users,
        "total_notifications": total_notifications,
        "recent_alerts": recent_alerts
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)