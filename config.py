import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///scanner.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_PAGES = int(os.getenv("MAX_PAGES", 30))
    MAX_DEPTH = int(os.getenv("MAX_DEPTH", 3))
    CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
    CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
