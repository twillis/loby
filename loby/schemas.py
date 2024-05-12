#!/usr/bin/env python3
import colander

class LoginSchema(colander.MappingSchema):
    username = colander.SchemaNode(colander.String(), validator=colander.Length(min=3))
    password = colander.SchemaNode(colander.String(), validator=colander.Length(min=5))

class RegisterSchema(colander.MappingSchema):
    username = colander.SchemaNode(colander.String(), validator=colander.Length(min=3))
    password = colander.SchemaNode(colander.String(), validator=colander.Length(min=5))
    confirm_password = colander.SchemaNode(colander.String(), validator=colander.Length(min=5))
    email = colander.SchemaNode(colander.String(), validator=colander.Email())

    def validator(self, node, value):
        # Check that password and confirm_password are the same
        if value['password'] != value['confirm_password']:
            raise colander.Invalid(node, "Passwords do not match")
