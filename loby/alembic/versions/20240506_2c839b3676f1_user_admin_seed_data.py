"""user admin seed data

Revision ID: 2c839b3676f1
Revises: ecbdeb53358b
Create Date: 2024-05-06 20:16:41.933185

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "2c839b3676f1"
down_revision: Union[str, None] = "ecbdeb53358b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass
    # import uuid
    # from loby import models

    # session = sa.orm.Session(bind=op.get_bind())
    # password_hash = hashpw("Password123$".encode("utf-8"), gensalt())
    # admin_user_sql = models.User.__table__.insert().values(
    #     user_name="admin", email="admin@email.com", password_hash=password_hash
    # )
    # breakpoint()
    # admin_user = session.execute(admin_user_sql)

    # role_sql = models.Role.__table__.insert().values(name="Admin")
    # role = session.execute(role_sql)

    # permission_sql = models.Permission.__table__.insert().values(name="edit")
    # permission = session.execute(permission_sql)

    # resource_sql = models.Resource.__table__.insert().values(name="users")
    # resource = session.execute(resource_sql)

    # role.permissions.append(permission)
    # resource.permissions.append(permission)
    # admin_user.roles.append(role)
    # session.commit()


def downgrade() -> None:
    pass
    # op.execute(
    #     "DELETE FROM user_roles WHERE user_id = (SELECT id FROM users WHERE user_name = 'admin')"
    # )
    # op.execute(
    #     "DELETE FROM role_permissions WHERE role_id = (SELECT id FROM roles WHERE name = 'Admin')"
    # )
    # op.execute(
    #     "DELETE FROM resource_permissions WHERE resource_id = (SELECT id FROM resources WHERE name = 'users')"
    # )
    # op.execute("DELETE FROM users WHERE user_name = 'admin'")
    # op.execute("DELETE FROM roles WHERE name = 'Admin'")
    # op.execute("DELETE FROM permissions WHERE name = 'edit'")
    # op.execute("DELETE FROM resources WHERE name = 'users'")
