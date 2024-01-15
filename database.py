from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

#POSTGRESQL LOCAL CONNECT
SQLALCHEMY_DATABASE_URL = 'postgresql://postgres:postgresql@localhost/TodoApplicationDatabase'
engine = create_engine(SQLALCHEMY_DATABASE_URL)

#SQlite3 CONNECT
#SQLALCHEMY_DATABASE_URL = 'sqlite:///./todosapp.db'
#engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={'check_same_thread': False})


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
