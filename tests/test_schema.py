import pytest
import colander
from loby import models
from loby.schema import make_model_schema


def test_make_schema(dbsession):
    schema = make_model_schema(models.User)
    assert schema.children

    with pytest.raises(colander.Invalid):
        schema.deserialize({})


def test_user_has_perm(dbsession):
    user = dbsession.query(models.User).filter_by(user_name="admin").one()
    assert models.user_has_permission(dbsession, user.id, "users", "edit"), "didnt work"
