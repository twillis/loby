#!/usr/bin/env python3
# loby/seeds/admin_user_role.py
from loby import models


def seed(session):
    admin_user = models.User(user_name="admin", email="admin@email.com")
    session.add(admin_user)
    admin_user.set_password("Password123$")

    role = models.Role(name="Admin")
    session.add(role)

    permission = models.Permission(name="edit")
    session.add(permission)

    resource = models.Resource(name="users")
    session.add(resource)

    role.permissions.append(permission)
    resource.permissions.append(permission)
    admin_user.roles.append(role)
