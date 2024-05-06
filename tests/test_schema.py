def test_make_schema(dbsession):
    from loby import models
    from loby.schema import make_model_schema
    schema = make_model_schema(models.User)
    assert schema.children
