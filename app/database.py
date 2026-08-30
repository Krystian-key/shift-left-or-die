from sqlalchemy import create_engine, or_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def search_scans_by_query(db, query: str) -> list:
    import models

    search_pattern = f"%{query}%"
    results = db.query(models.ScanResult).filter(
        or_(
            models.ScanResult.title.like(search_pattern),
            models.ScanResult.description.like(search_pattern),
            models.ScanResult.cve_id.like(search_pattern)
        )
    ).all()
    return [dict(row.__dict__) for row in results if '_sa_instance_state' not in row.__dict__]
