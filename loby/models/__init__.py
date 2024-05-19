"""Make sure models are all imported here"""
from pyramid_sqlalchemy import BaseObject
from sqlalchemy import Column, String, UUID, ForeignKey, Table, Boolean
from bcrypt import hashpw, gensalt, checkpw
from sqlalchemy.orm import relationship, Session, joinedload, aliased
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
    verified = Column(Boolean, nullable=False, default=False)

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
    allow = Column(Boolean, nullable=False)  # True for allow, False for deny


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

    user = (
        session.query(User)
        .options(
            joinedload(User.roles)
            .joinedload(Role.permissions)
            .joinedload(Permission.resources)
        )
        .filter(User.id == user_id, Permission.allow == True)
        .one_or_none()
    )

    if not user:
        return False

    # Split resource_name into segments for matching
    resource_segments = resource_name.split(".")
    permissions = []

    for role in user.roles:
        for permission in role.permissions:
            for resource in permission.resources:
                resource_segments_check = resource.name.split(".")
                if len(resource_segments_check) > len(resource_segments):
                    continue

                if (
                    resource_segments[: len(resource_segments_check)]
                    == resource_segments_check
                ):
                    permissions.append((len(resource_segments_check), permission.allow))

    if not permissions:
        return False

    # Sort by specificity (length) and get the most specific permission
    permissions.sort(key=lambda x: x[0], reverse=True)
    most_specific_permission = permissions[0][1]

    return most_specific_permission


"""
new permission strategy




resource_name should match to a route name with caveats...

given route name admin.users.create and admin.user.edit

I can Allow or Deny a permission to a Role by specifying a resource_name as any of the following

Allow,"admin.user.create"
Allow,"admin.user.*"
Allow,"admin.*"
Allow,"*"

in the case that a user has been granted and denied a permission on a resource the permission that wins is the most specific one

given
Allow,"admin.user"
Deny, "admin.user.create"

in this case the user is denied access to admin.user.create but is allowed to list the user list view and admin.users.update
given
Deny,"admin.user"
Allow "admin.user.update"

would indicate that the user cannot see the user list, but is allowed access to update users.

I need changes to the existing model and a new implementation of user_has_permission based on these new requirements
"""
