#!/usr/bin/env python3
from loby import models

def get_or_create(session, model, **criteria):
    m = session.query(model).filter_by(**criteria).one_or_none()
    if not m:
        m = model(**criteria)
        session.add(m)

    return m



def create_or_update_admin_user(session):
    admin_user = get_or_create(session, models.User, user_name="admin")
    admin_user.email = "admin@email.com"
    admin_user.set_password("Password123$")
    admin_user.verified = True
    return admin_user

def create_or_update_admin_role(session):
    admin_role = get_or_create(session, models.Role, name="Admin")
    allow_edit_permission = get_or_create(session, models.Permission,name="edit", allow=True)
    allow_view_permission = get_or_create(session, models.Permission,name="view", allow=True)

    resource = get_or_create(session, models.Resource, name="admin.user")

    admin_role.permissions.append(allow_edit_permission) if "edit" not in [r.name for r in admin_role.permissions] else None
    resource.permissions.append(allow_edit_permission) if "edit" not in [r.name for r in resource.permissions] else None
    admin_role.permissions.append(allow_view_permission) if "view" not in [r.name for r in admin_role.permissions] else None
    resource.permissions.append(allow_view_permission) if "view" not in [r.name for r in resource.permissions] else None
    return admin_role

def seed(session):
    admin_user = create_or_update_admin_user(session)
    admin_role = create_or_update_admin_role(session)
    admin_user.roles.append(admin_role) if admin_role.name not in [r.name for r in admin_user.roles] else None
