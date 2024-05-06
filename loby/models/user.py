from pyramid_sqlalchemy import BaseObject
from sqlalchemy import Column, String, UUID
from bcrypt import hashpw, gensalt, checkpw
import uuid

class User(BaseObject):
    __tablename__ = "user"

    id = Column(UUID, primary_key=True, default=uuid.uuid4)
    user_name = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)

    def __init__(self, user_name, email, password):
        self.user_name = user_name
        self.email = email
        self.set_password(password)

    def set_password(self, password):
        self.password_hash = hashpw(password.encode("utf-8"), gensalt()).decode("utf-8")

    def check_password(self, password):
        return checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))
