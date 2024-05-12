"""Make sure models are all imported here"""
from pyramid_sqlalchemy import BaseObject
from sqlalchemy import Column, String, UUID, ForeignKey, Table, Boolean
from bcrypt import hashpw, gensalt, checkpw
from sqlalchemy.orm import relationship, Session
import uuid

user_role_table = Table(
    "user_role",
    BaseObject.metadata,
    Column(
        "user_id", UUID, ForeignKey("user.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "role_id", UUID, ForeignKey("role.id", ondelete="CASCADE"), primary_key=True
    ),
)

role_permission_table = Table(
    "role_permission",
    BaseObject.metadata,
    Column(
        "role_id", UUID, ForeignKey("role.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "permission_id",
        UUID,
        ForeignKey("permission.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

resource_permission_table = Table(
    "resource_permission",
    BaseObject.metadata,
    Column(
        "resource_id",
        UUID,
        ForeignKey("resource.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "permission_id",
        UUID,
        ForeignKey("permission.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class User(BaseObject):
    __tablename__ = "user"

    id = Column(UUID, primary_key=True, default=uuid.uuid4)
    user_name = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    verified = Column(Boolean, nullable=False)

    def set_password(self, password):
        self.password_hash = hashpw(password.encode("utf-8"), gensalt()).decode("utf-8")

    def check_password(self, password):
        return checkpw(password.encode("utf-8"), self.password_hash.encode("utf-8"))

    roles = relationship("Role", secondary=user_role_table, back_populates="users")


class Role(BaseObject):
    __tablename__ = "role"

    id = Column(UUID, primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True, nullable=False)

    users = relationship("User", secondary=user_role_table, back_populates="roles")
    permissions = relationship(
        "Permission", secondary=role_permission_table, back_populates="roles"
    )


class Permission(BaseObject):
    __tablename__ = "permission"

    id = Column(UUID, primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True, nullable=False)

    roles = relationship(
        "Role", secondary=role_permission_table, back_populates="permissions"
    )
    resources = relationship(
        "Resource", secondary=resource_permission_table, back_populates="permissions"
    )


class Resource(BaseObject):
    __tablename__ = "resource"

    id = Column(UUID, primary_key=True, default=uuid.uuid4)
    name = Column(String, unique=True, nullable=False)
    permissions = relationship(
        "Permission", secondary=resource_permission_table, back_populates="resources"
    )


def user_has_permission(
    session: Session, user_id: str, resource_name: str, permission_name: str
) -> bool:
    return (
        session.query(User)
        .join(User.roles)
        .join(Role.permissions)
        .join(Permission.resources)
        .filter(
            User.id == user_id,
            Resource.name == resource_name,
            Permission.name == permission_name,
        )
        .count()
        > 0
    )
