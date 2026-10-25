import os
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


def database_url():
    url = os.getenv('DATABASE_URL', 'sqlite:///./moreda_local.db')
    if url.startswith('postgres://'):
        url = 'postgresql+psycopg://' + url[len('postgres://'):]
    elif url.startswith('postgresql://'):
        url = 'postgresql+psycopg://' + url[len('postgresql://'):]
    return url


class Base(DeclarativeBase):
    pass


engine = create_engine(
    database_url(), pool_pre_ping=True,
    connect_args={'check_same_thread': False} if database_url().startswith('sqlite:') else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    with SessionLocal() as session:
        yield session
