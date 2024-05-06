import pytest
import colander
from loby import models
from loby.schema import make_model_schema


def test_make_schema(dbsession):
    schema = make_model_schema(models.User)
    assert schema.children

    with pytest.raises(colander.Invalid):
        schema.deserialize({})
