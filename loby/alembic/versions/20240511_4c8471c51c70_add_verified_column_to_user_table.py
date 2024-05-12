"""Add verified column to user table

Revision ID: 4c8471c51c70
Revises: 2c839b3676f1
Create Date: 2024-05-11 17:28:37.199890

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4c8471c51c70'
down_revision: Union[str, None] = '2c839b3676f1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # Adding a new column 'verified' to the 'users' table
    op.add_column('user', sa.Column('verified', sa.Boolean(), nullable=False, server_default=sa.false()))

def downgrade():
    # Removing the column 'verified' from the 'users' table
    op.drop_column('user', 'verified')
