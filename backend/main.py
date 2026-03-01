from fastapi import FastAPI, File, UploadFile, HTTPException, Form, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Optional
from pydantic import BaseModel

from backend.utils.hashing import generate_hash
from backend.identity.sign import sign_hash, verify_signature
from backend.identity.issuers import list_issuers, get_issuer, ISSUER_REGISTRY
from backend.identity.keygen import run as generate_all_keys
from backend.blockchain.blockchain import anchor_hash, verify_chain, load_chain
from backend.anomaly.logger import log_event
from backend.anomaly.detector import detect_anomaly
from backend.response.responder import autonomous_response
from backend.utils.file_validator import validate_file
from backend.utils.excel_parser import parse_excel

from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import json
import time
import os
import uuid

# ──────────────────────────────────────────────────────────────────────────────
# App Initialization
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Veracity Agent – Autonomous AI Trust System",
    description="Multi-issuer document integrity, authenticity & blockchain provenance system",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")
LEDGER_PATH = os.path.join(STORAGE_DIR, "local_ledger.json")
USERS_PATH  = os.path.join(STORAGE_DIR, "users.json")

# ──────────────────────────────────────────────────────────────────────────────
# JWT / Auth Config
# ──────────────────────────────────────────────────────────────────────────────
SECRET_KEY = "veracity-agent-super-secret-key-change-in-production"
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ──────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ──────────────────────────────────────────────────────────────────────────────
class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    username: str
    email: str

# ──────────────────────────────────────────────────────────────────────────────
# User store helpers
# ──────────────────────────────────────────────────────────────────────────────
def load_users():
    if not os.path.exists(USERS_PATH):
        return {"users": []}
    try:
        with open(USERS_PATH, "r") as f:
            return json.load(f)
    except:
        return {"users": []}

def save_users(data):
    os.makedirs(STORAGE_DIR, exist_ok=True)
    with open(USERS_PATH, "w") as f:
        json.dump(data, f, indent=4)

def get_user_by_username(username: str):
    store = load_users()
    for u in store["users"]:
        if u["username"] == username:
            return u
    return None

def get_user_by_email(email: str):
    store = load_users()
    for u in store["users"]:
        if u["email"] == email:
            return u
    return None

def get_user_by_id(user_id: str):
    store = load_users()
    for u in store["users"]:
        if u["id"] == user_id:
            return u
    return None

# ──────────────────────────────────────────────────────────────────────────────
# JWT helpers
# ──────────────────────────────────────────────────────────────────────────────
def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_id(user_id)
    if user is None:
        raise credentials_exception
    return user

# ──────────────────────────────────────────────────────────────────────────────
# Startup: ensure all issuer keys exist
# ──────────────────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup_event():
    generate_all_keys()

# ──────────────────────────────────────────────────────────────────────────────
# Ledger Helpers
# ──────────────────────────────────────────────────────────────────────────────
def load_ledger():
    if not os.path.exists(LEDGER_PATH):
        return {"records": []}
    try:
        with open(LEDGER_PATH, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {"records": []}


def save_ledger(data):
    os.makedirs(STORAGE_DIR, exist_ok=True)
    with open(LEDGER_PATH, "w") as f:
        json.dump(data, f, indent=4)


def hash_exists_for_user(ledger, file_hash: str, user_id: str) -> bool:
    """Check if the same hash already registered by this specific user."""
    return any(
        r["hash"] == file_hash and r.get("user_id") == user_id
        for r in ledger.get("records", [])
    )

def find_existing_hash_owner(ledger, file_hash: str, current_user_id: str):
    """Find if another user already registered this hash (copy detection)."""
    for r in ledger.get("records", []):
        if r["hash"] == file_hash and r.get("user_id") != current_user_id:
            return r.get("uploaded_by", "another user")
    return None


def _build_record(filename, file_hash, signature, issuer_did, file_info: dict, user_id: str, username: str) -> dict:
    return {
        "filename":       filename,
        "hash":           file_hash,
        "signature":      signature,
        "issuer_did":     issuer_did,
        "issuer_name":    ISSUER_REGISTRY[issuer_did]["name"],
        "signature_algo": "RSA-PSS-SHA256",
        "issued_at":      time.time(),
        "revoked":        False,
        "file_type":      file_info.get("category", "other"),
        "mime_type":      file_info.get("mime_type", ""),
        "size_bytes":     file_info.get("size_bytes", 0),
        "user_id":        user_id,
        "uploaded_by":    username,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Verify Helper (shared between single + batch)
# ──────────────────────────────────────────────────────────────────────────────
def _verify_content(content: bytes, filename: str, start_time: float, user_id: str) -> dict:
    incoming_hash = generate_hash(content)
    ledger = load_ledger()

    # Search in this user's records only
    for record in ledger.get("records", []):
        if record["hash"] == incoming_hash and record.get("user_id") == user_id:
            if record.get("revoked", False):
                return {
                    "filename":   filename,
                    "status":     "REVOKED",
                    "issuer":     record["issuer_did"],
                    "issuer_name": record.get("issuer_name", ""),
                    "latency_ms": round((time.time() - start_time) * 1000, 2),
                    "reason":     "Credential revoked by autonomous agent",
                }

            if record["issuer_did"] not in ISSUER_REGISTRY:
                return {
                    "filename":   filename,
                    "status":     "REJECTED",
                    "latency_ms": round((time.time() - start_time) * 1000, 2),
                    "reason":     "Untrusted issuer",
                }

            sig_valid = verify_signature(
                incoming_hash,
                record["signature"],
                record["issuer_did"]
            )

            log_event(event_type="verify", details={"count": 1, "hash": incoming_hash})
            latency_ms = round((time.time() - start_time) * 1000, 2)

            if sig_valid:
                return {
                    "filename":   filename,
                    "status":     "VERIFIED",
                    "issuer":     record["issuer_did"],
                    "issuer_name": record.get("issuer_name", ""),
                    "integrity":  "HASH MATCHED",
                    "authenticity": "SIGNATURE VALID",
                    "provenance": "BLOCKCHAIN ANCHORED",
                    "file_type":  record.get("file_type", ""),
                    "mime_type":  record.get("mime_type", ""),
                    "issued_at":  record.get("issued_at"),
                    "latency_ms": latency_ms,
                }
            else:
                return {
                    "filename":   filename,
                    "status":     "REJECTED",
                    "latency_ms": latency_ms,
                    "reason":     "Signature verification failed",
                }

    return {
        "filename":   filename,
        "status":     "TAMPERED OR UNKNOWN",
        "latency_ms": round((time.time() - start_time) * 1000, 2),
        "reason":     "Hash not found in your ledger",
    }


# ==============================================================================
# 🔐 AUTH ENDPOINTS
# ==============================================================================
@app.post("/auth/register", response_model=Token)
def register(payload: UserRegister):
    """Register a new user account."""
    if get_user_by_username(payload.username):
        raise HTTPException(status_code=400, detail="Username already taken")
    if get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = str(uuid.uuid4())
    hashed_pw = hash_password(payload.password)
    new_user = {
        "id":              user_id,
        "username":        payload.username,
        "email":           payload.email,
        "hashed_password": hashed_pw,
        "created_at":      time.time(),
    }
    store = load_users()
    store["users"].append(new_user)
    save_users(store)

    token = create_access_token({"sub": user_id})
    return Token(access_token=token, token_type="bearer",
                 username=payload.username, email=payload.email)


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Login with username + password, returns JWT."""
    user = get_user_by_username(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    token = create_access_token({"sub": user["id"]})
    return Token(access_token=token, token_type="bearer",
                 username=user["username"], email=user["email"])


@app.get("/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    """Return current user info."""
    return {
        "id":       current_user["id"],
        "username": current_user["username"],
        "email":    current_user["email"],
        "created_at": current_user.get("created_at"),
    }


# ==============================================================================
# 📋 ISSUER REGISTRY
# ==============================================================================
@app.get("/issuers")
def get_issuers():
    """Return all trusted issuers."""
    return {"issuers": list_issuers()}


# ==============================================================================
# 📥 SINGLE FILE REGISTER / SIGN / ANCHOR  (auth required)
# ==============================================================================
@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    issuer_did: Optional[str] = Form(default="did:veracity:mlritm"),
    current_user: dict = Depends(get_current_user),
):
    start_time = time.time()

    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded")

    if issuer_did not in ISSUER_REGISTRY:
        raise HTTPException(status_code=400, detail=f"Unknown issuer: {issuer_did}")

    content = await file.read()

    file_info = validate_file(content, file.filename)
    if not file_info["valid"]:
        raise HTTPException(status_code=422, detail=f"Invalid file: {file_info['message']}")

    file_hash = generate_hash(content)
    ledger = load_ledger()

    if hash_exists_for_user(ledger, file_hash, current_user["id"]):
        raise HTTPException(status_code=409, detail="Replay detected: File already registered by you")

    # Copy detection
    copy_owner = find_existing_hash_owner(ledger, file_hash, current_user["id"])

    signature = sign_hash(file_hash, issuer_did)
    record = _build_record(file.filename, file_hash, signature, issuer_did, file_info,
                           current_user["id"], current_user["username"])
    ledger["records"].append(record)
    save_ledger(ledger)

    block = anchor_hash(file_hash, issuer_did)
    log_event(event_type="upload", details={"count": 1, "hash": file_hash})

    latency_ms = round((time.time() - start_time) * 1000, 2)

    extra = {}
    if file_info["category"] == "spreadsheet":
        extra["spreadsheet_info"] = parse_excel(content, file.filename)

    response = {
        "message":        "File registered, signed, and anchored",
        "hash":           file_hash,
        "issuer":         issuer_did,
        "issuer_name":    ISSUER_REGISTRY[issuer_did]["name"],
        "file_type":      file_info["category"],
        "mime_type":      file_info["mime_type"],
        "size_bytes":     file_info["size_bytes"],
        "block_index":    block["index"],
        "block_hash":     block["block_hash"],
        "upload_latency_ms": latency_ms,
        "uploaded_by":    current_user["username"],
        **extra,
    }

    if copy_owner:
        response["copy_detected"] = True
        response["copy_of_user"] = copy_owner

    return response


# ==============================================================================
# 📦 BATCH REGISTER (multiple files, one issuer)  (auth required)
# ==============================================================================
@app.post("/upload/batch")
async def upload_batch(
    files: List[UploadFile] = File(...),
    issuer_did: Optional[str] = Form(default="did:veracity:mlritm"),
    current_user: dict = Depends(get_current_user),
):
    if issuer_did not in ISSUER_REGISTRY:
        raise HTTPException(status_code=400, detail=f"Unknown issuer: {issuer_did}")

    ledger = load_ledger()
    results = []

    for f in files:
        start_time = time.time()
        try:
            content = await f.read()
            file_info = validate_file(content, f.filename)

            if not file_info["valid"]:
                results.append({
                    "filename": f.filename,
                    "status":   "FAILED",
                    "reason":   file_info["message"],
                    "latency_ms": 0,
                })
                continue

            file_hash = generate_hash(content)

            if hash_exists_for_user(ledger, file_hash, current_user["id"]):
                results.append({
                    "filename":  f.filename,
                    "status":    "DUPLICATE",
                    "reason":    "Already registered by you",
                    "hash":      file_hash,
                    "latency_ms": round((time.time() - start_time) * 1000, 2),
                })
                continue

            copy_owner = find_existing_hash_owner(ledger, file_hash, current_user["id"])

            signature = sign_hash(file_hash, issuer_did)
            record = _build_record(f.filename, file_hash, signature, issuer_did, file_info,
                                   current_user["id"], current_user["username"])
            ledger["records"].append(record)

            block = anchor_hash(file_hash, issuer_did)
            log_event(event_type="upload", details={"count": 1, "hash": file_hash})

            result_entry = {
                "filename":   f.filename,
                "status":     "REGISTERED",
                "hash":       file_hash,
                "file_type":  file_info["category"],
                "mime_type":  file_info["mime_type"],
                "block_index": block["index"],
                "latency_ms": round((time.time() - start_time) * 1000, 2),
            }
            if copy_owner:
                result_entry["copy_detected"] = True
                result_entry["copy_of_user"] = copy_owner

            results.append(result_entry)

        except Exception as e:
            results.append({
                "filename": f.filename,
                "status":   "ERROR",
                "reason":   str(e),
                "latency_ms": 0,
            })

    save_ledger(ledger)
    return {
        "issuer":       issuer_did,
        "issuer_name":  ISSUER_REGISTRY[issuer_did]["name"],
        "total_files":  len(files),
        "results":      results,
    }


# ==============================================================================
# 🔍 SINGLE FILE VERIFY  (auth required)
# ==============================================================================
@app.post("/verify")
async def verify_file(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    start_time = time.time()
    if not file:
        raise HTTPException(status_code=400, detail="No file uploaded")

    content = await file.read()
    return _verify_content(content, file.filename, start_time, current_user["id"])


# ==============================================================================
# 🔍 BATCH VERIFY (auth required)
# ==============================================================================
@app.post("/verify/batch")
async def verify_batch(
    files: List[UploadFile] = File(...),
    current_user: dict = Depends(get_current_user),
):
    results = []
    for f in files:
        start_time = time.time()
        content = await f.read()
        result = _verify_content(content, f.filename, start_time, current_user["id"])
        results.append(result)
    return {
        "total_files": len(files),
        "results": results,
    }


# ==============================================================================
# 📊 EXCEL / SPREADSHEET PARSE (no auth required – preview only)
# ==============================================================================
@app.post("/parse/spreadsheet")
async def parse_spreadsheet(file: UploadFile = File(...)):
    content = await file.read()
    result = parse_excel(content, file.filename)
    return result


# ==============================================================================
# 📘 LEDGER VIEWER  (auth required – user-scoped)
# ==============================================================================
@app.get("/ledger/view")
def view_ledger(current_user: dict = Depends(get_current_user)):
    ledger = load_ledger()
    user_records = [r for r in ledger.get("records", []) if r.get("user_id") == current_user["id"]]
    return {"records": user_records}


# ==============================================================================
# 🗑️ LEDGER CLEAR  (auth required – clears current user's records only)
# ==============================================================================
@app.delete("/ledger/clear")
def clear_ledger(current_user: dict = Depends(get_current_user)):
    """Remove all records belonging to the current user."""
    ledger = load_ledger()
    before = len(ledger.get("records", []))
    ledger["records"] = [r for r in ledger.get("records", []) if r.get("user_id") != current_user["id"]]
    removed = before - len(ledger["records"])
    save_ledger(ledger)
    log_event(event_type="clear_ledger", details={"removed_records": removed})
    return {
        "message": "Your ledger records cleared",
        "records_removed": removed,
    }


# ==============================================================================
# ⛓️ BLOCKCHAIN HEALTH CHECK
# ==============================================================================
@app.get("/blockchain/verify")
def blockchain_health_check():
    return {"blockchain_valid": verify_chain()}


# ==============================================================================
# ⛓️ BLOCKCHAIN BLOCK EXPLORER
# ==============================================================================
@app.get("/blockchain/blocks")
def view_blockchain_blocks():
    chain = load_chain()
    return {"total_blocks": len(chain), "chain": chain}


# ==============================================================================
# 🧠 AI ANOMALY DETECTION
# ==============================================================================
@app.get("/anomaly/check")
def anomaly_check():
    return detect_anomaly()


# ==============================================================================
# 🤖 AUTONOMOUS AGENT RESPONSE
# ==============================================================================
@app.post("/agent/respond")
def agent_autonomous_response():
    anomaly_result = detect_anomaly()
    response = autonomous_response(anomaly_result)
    return {
        "anomaly_result": anomaly_result,
        "agent_action":   response,
    }
