import colander
from sqlalchemy.orm import DeclarativeMeta
from sqlalchemy import inspect
from sqlalchemy import Integer, String, Float, Boolean, DateTime, Text
from sqlalchemy.dialects.postgresql import UUID


def column_to_colander_node(column):
    column_type = column.type.__class__

    missing = colander.required if not column.nullable else None

    if column_type in [Integer]:
        return colander.SchemaNode(colander.Int(), name=column.name, missing=missing)
    elif column_type in [String, Text, UUID]:
        return colander.SchemaNode(colander.String(), name=column.name, missing=missing)
    elif column_type in [Float]:
        return colander.SchemaNode(colander.Float(), name=column.name, missing=missing)
    elif column_type in [Boolean]:
        return colander.SchemaNode(colander.Boolean(), name=column.name, missing=missing)
    elif column_type in [DateTime]:
        return colander.SchemaNode(colander.DateTime(), name=column.name, missing=missing)
    else:
        raise ValueError(f"Unsupported column type: {column_type}")


def make_model_schema(model_class):
    if not isinstance(model_class, DeclarativeMeta):
        raise TypeError("Expected a SQLAlchemy model class")

    schema = colander.MappingSchema(name=f"{model_class.__name__}Schema", description="auto generated from a sqlalchemy model")

    for column_name, column in inspect(model_class).columns.items():
        node = column_to_colander_node(column)
        schema.add(node)

    return schema


# Usage example
# schema = make_schema(YourSQLAlchemyModelClass)
