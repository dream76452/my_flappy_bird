from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import create_engine, Column, Integer, String, DateTime, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import hashlib
from datetime import datetime
import uvicorn

# ⚠️ WARNING: /tmp is writable on Vercel, but data is erased between serverless invocations.
# For production, replace this with a cloud database (e.g., Vercel Postgres, Supabase).
SQLALCHEMY_DATABASE_URL = "sqlite:////tmp/flappybird.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def simple_hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(plain_password, hashed_password):
    return simple_hash_password(plain_password) == hashed_password

def get_password_hash(password):
    return simple_hash_password(password)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

class Score(Base):
    __tablename__ = "scores"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    score = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)

# Initialize database tables
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

security = HTTPBasic()

def get_current_user(
    credentials: HTTPBasicCredentials = Depends(security), 
    db: Session = Depends(get_db)
):
    username = credentials.username
    password = credentials.password
    
    if not password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Password required", headers={"WWW-Authenticate": "Basic"})
    
    user = db.query(User).filter(User.username == username).first()
    
    if not user:
        user = User(username=username, hashed_password=get_password_hash(password))
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        if not verify_password(password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password", headers={"WWW-Authenticate": "Basic"})
    return user

# This 'app' variable is required by Vercel
app = FastAPI(title="Flappy Bird API")

@app.get("/api/stats")
def get_user_stats(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.query(func.max(Score.score)).filter(Score.user_id == user.id).scalar() or 0
    last_score_obj = db.query(Score.score).filter(Score.user_id == user.id).order_by(Score.created_at.desc()).first()
    last_result = last_score_obj[0] if last_score_obj else 0
    return {"username": user.username, "record": record, "last_result": last_result}

@app.post("/api/score")
def save_score(score: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    new_score = Score(user_id=user.id, score=score)
    db.add(new_score)
    db.commit()
    return {"status": "success", "score": score}

@app.get("/api/leaderboard")
def get_leaderboard(db: Session = Depends(get_db)):
    subquery = db.query(
        Score.user_id,
        func.max(Score.score).label('max_score'),
        func.max(Score.created_at).label('last_run')
    ).group_by(Score.user_id).subquery()

    results = db.query(
        User.username,
        subquery.c.max_score,
        subquery.c.last_run
    ).join(subquery, User.id == subquery.c.user_id)\
     .order_by(subquery.c.max_score.desc())\
     .limit(10).all()

    return [{"username": r[0], "max_score": r[1], "last_run": r[2].isoformat() if r[2] else None} for r in results]
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)