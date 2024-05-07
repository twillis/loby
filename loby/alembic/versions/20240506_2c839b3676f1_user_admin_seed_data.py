"""user admin seed data

Revision ID: 2c839b3676f1
Revises: ecbdeb53358b
Create Date: 2024-05-06 20:16:41.933185

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2c839b3676f1'
down_revision: Union[str, None] = 'ecbdeb53358b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    import uuid
    from loby import models
    session = sa.orm.Session(bind=op.get_bind())
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
    session.commit()


def downgrade() -> None:
    pass
