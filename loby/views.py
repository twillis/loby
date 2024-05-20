from pyramid.view import view_config, forbidden_view_config
from pyramid.httpexceptions import HTTPFound, HTTPUnauthorized, HTTPForbidden
from pyramid_sqlalchemy import Session
from .models import User, Permission, Role, Resource
from .schemas import LoginSchema, RegisterSchema
import colander
from pyramid.security import remember, forget


@view_config(route_name="login", renderer="templates/login.html", request_method="GET")
def login_get_view(request):
    return {}


@view_config(route_name="login", renderer="templates/login.html", request_method="POST")
def login_post_view(request):
    schema = LoginSchema()
    try:
        # Deserialize and validate
        appstruct = schema.deserialize(request.POST)
    except colander.Invalid as e:
        request.response.status_int = 400
        return {"errors": e.asdict()}

    user = (
        Session.query(User)
        .filter_by(user_name=appstruct["username"], verified=True)
        .first()
    )

    if user and user.check_password(appstruct["password"]):
        headers = remember(request, str(user.id))
        return HTTPFound(location=request.route_url("home"), headers=headers)

    request.response.status_int = 401
    return {"errors": {"login": "Invalid username or password"}}


@view_config(route_name="logout")
def logout_view(request):
    headers = forget(request)
    return HTTPFound(location=request.route_url("login"), headers=headers)


@view_config(route_name="home", renderer="templates/home.html")
def home_view(request):
    return {}


@view_config(route_name="register", renderer="templates/register.html")
def register_view(request):
    return {}


@view_config(
    route_name="register", renderer="templates/register.html", request_method="POST"
)
def register_post_view(request):
    schema = RegisterSchema()
    try:
        # Deserialize and validate
        appstruct = schema.deserialize(request.POST)
    except colander.Invalid as e:
        request.response.status_int = 400
        return {"errors": e.asdict(), "form_data": request.POST}

    session = Session()
    user = session.query(User).filter_by(user_name=appstruct["username"]).first()
    if user:
        request.response.status_int = 400
        return {
            "errors": {"username": "Username already exists"},
            "form_data": request.POST,
        }

    new_user = User(user_name=appstruct["username"], email=appstruct["email"])
    new_user.set_password(appstruct["password"])
    session.add(new_user)
    session.flush()
    request.session.flash("Registration successful! You can now log in.")
    return HTTPFound(location=request.route_url("login"))


@view_config(
    route_name="admin.user", renderer="templates/edit_user.html", permission="edit"
)
def user_index_view(request):
    assert request.authenticated_userid
    assert request.has_permission("edit")
    # Assuming the user is trying to edit details here
    return {"users": Session.query(User).all()}


@view_config(
    route_name="admin.user.edit",
    renderer="templates/edit_user.html",
    request_method="POST",
    permission="edit",
)
@view_config(
    route_name="admin.user.create",
    renderer="templates/user_form.html",
    request_method="POST",
    permission="edit",
)
def user_save_view(request):
    session = Session()
    user_id = request.matchdict.get("user_id", None)
    user = session.query(User).filter_by(id=user_id).first() if user_id else User()
    user.user_name = request.params["user_name"]
    user.email = request.params["email"]
    user.verified = request.params["verified"] == "true"
    password = (
        request.params.get("password", None) if user else request.params["password"]
    )

    if password:
        user.set_password(password)

    if not user_id:  # This means it's a new user
        session.add(user)

    session.flush()
    return HTTPFound(location=request.route_url("admin.user"))


@view_config(
    route_name="admin.user.edit",
    renderer="templates/user_form.html",
    request_method="GET",
    permission="edit",
)
def user_edit_form(request):
    user_id = request.matchdict.get("user_id")
    user = Session().query(User).filter_by(id=user_id).one()
    return {"user": user, "errors": {}}


@view_config(
    route_name="admin.user.create",
    renderer="templates/user_form.html",
    request_method="GET",
    permission="edit",
)
def user_create_form(request):
    return {"user": None, "errors": {}}


@view_config(
    route_name="admin", renderer="templates/admin/index.html"
)
def admin_index(request):
    return {}


# Roles views
@view_config(
    route_name="admin.roles",
    renderer="templates/admin/roles/index.html",
    permission="edit",
)
def admin_roles_index(request):
    roles = request.dbsession.query(Role).all()
    return {"roles": roles}


@view_config(
    route_name="admin.roles.create",
    renderer="templates/admin/roles/form.html",
    permission="edit",
)
def admin_roles_create(request):
    if request.method == "POST":
        name = request.params["name"]
        new_role = Role(name=name)
        request.dbsession.add(new_role)
        return HTTPFound(location=request.route_url("admin.roles"))
    return {}


@view_config(
    route_name="admin.roles.edit",
    renderer="templates/admin/roles/edit.html",
    permission="edit",
)
def admin_roles_edit(request):
    role_id = request.matchdict["role_id"]
    role = request.dbsession.query(Role).filter_by(id=role_id).one()
    if request.method == "POST":
        role.name = request.params["name"]
        # Manage permissions here
        return HTTPFound(location=request.route_url("admin.roles"))
    permissions = request.dbsession.query(Permission).all()
    return {"role": role, "permissions": permissions}


# Permissions views
@view_config(
    route_name="admin.permissions",
    renderer="templates/admin/permissions/index.html",
    permission="edit",
)
def admin_permissions_index(request):
    permissions = request.dbsession.query(Permission).all()
    return {"permissions": permissions}


@view_config(
    route_name="admin.permissions.create",
    renderer="templates/admin/permissions/form.html",
    permission="edit",
)
def admin_permissions_create(request):
    if request.method == "POST":
        name = request.params["name"]
        new_permission = Permission(name=name)
        request.dbsession.add(new_permission)
        return HTTPFound(location=request.route_url("admin.permissions"))
    return {}


@view_config(
    route_name="admin.permissions.edit",
    renderer="templates/admin/permissions/edit.html",
    permission="edit",
)
def admin_permissions_edit(request):
    permission_id = request.matchdict["permission_id"]
    permission = request.dbsession.query(Permission).filter_by(id=permission_id).one()
    if request.method == "POST":
        permission.name = request.params["name"]
        # Manage roles here
        return HTTPFound(location=request.route_url("admin.permissions"))
    roles = request.dbsession.query(Role).all()
    return {"permission": permission, "roles": roles}


# Resources views
@view_config(
    route_name="admin.resources",
    renderer="templates/admin/resources/index.html",
    permission="edit",
)
def admin_resources_index(request):
    resources = request.dbsession.query(Resource).all()
    return {"resources": resources}


@view_config(
    route_name="admin.resources.create",
    renderer="templates/admin/resources/form.html",
    permission="edit",
)
def admin_resources_create(request):
    if request.method == "POST":
        name = request.params["name"]
        new_resource = Resource(name=name)
        request.dbsession.add(new_resource)
        return HTTPFound(location=request.route_url("admin.resources"))
    return {}


@view_config(
    route_name="admin.resources.edit",
    renderer="templates/admin/resources/edit.html",
    permission="edit",
)
def admin_resources_edit(request):
    resource_id = request.matchdict["resource_id"]
    resource = request.dbsession.query(Resource).filter_by(id=resource_id).one()
    if request.method == "POST":
        resource.name = request.params["name"]
        # Manage permissions here
        return HTTPFound(location=request.route_url("admin.resources"))
    permissions = request.dbsession.query(Permission).all()
    return {"resource": resource, "permissions": permissions}


# In your views_admin.py or another appropriate views file
@view_config(route_name="admin.api.permissions", renderer="json", permission="edit")
def api_permissions(request):
    term = request.params.get('term', '')
    permissions = request.dbsession.query(Permission).filter(Permission.name.ilike(f'%{term}%')).all()
    return [{'id': p.id, 'name': p.name} for p in permissions]

@view_config(route_name="admin.api.roles", renderer="json", permission="edit")
def api_roles(request):
    term = request.params.get('term', '')
    roles = request.dbsession.query(Role).filter(Role.name.ilike(f'%{term}%')).all()
    return [{'id': r.id, 'name': r.name} for r in roles]

@forbidden_view_config()
def custom_forbidden_view(request):
    # If the user is not authenticated, raise 401 Unauthorized
    if not request.authenticated_userid:
        return HTTPUnauthorized()
    return HTTPForbidden()
