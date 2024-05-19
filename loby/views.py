from pyramid.view import view_config, forbidden_view_config
from pyramid.httpexceptions import HTTPFound, HTTPUnauthorized, HTTPForbidden
from pyramid_sqlalchemy import Session
from .models import User
from .schemas import LoginSchema, RegisterSchema
import colander
from pyramid.security import remember

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

    user = Session.query(User).filter_by(user_name=appstruct["username"]).first()

    if user and user.check_password(appstruct["password"]):
        headers = remember(request, str(user.id))
        return HTTPFound(location=request.route_url("home"), headers=headers)

    request.response.status_int = 401
    return {"errors": {"login": "Invalid username or password"}}


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

@view_config(route_name='admin.user', renderer='templates/edit_user.html', permission='edit')
def user_index_view(request):
    assert request.authenticated_userid
    assert request.has_permission("edit")
    # Assuming the user is trying to edit details here
    return {"users": Session.query(User).all()}


@view_config(route_name='admin.user.edit', renderer='templates/edit_user.html', request_method='POST', permission='edit')
@view_config(route_name='admin.user.create', renderer='templates/user_form.html', request_method='POST', permission='edit')
def user_save_view(request):
    session = Session()
    user_id = request.matchdict.get('user_id', None)
    user = session.query(User).filter_by(id=user_id).first() if user_id else User()
    user.user_name = request.params['user_name']
    user.email = request.params['email']
    user.verified = request.params['verified'] == 'true'
    password = request.params.get("password", None) if user else request.params["password"]

    if password:
        user.set_password(password)

    if not user_id:  # This means it's a new user
        session.add(user)

    session.flush()
    return HTTPFound(location=request.route_url("admin.user"))



@view_config(route_name='admin.user.edit', renderer='templates/user_form.html', request_method='GET', permission='edit')
def user_edit_form(request):
    user_id = request.matchdict.get("user_id")
    user = Session().query(User).filter_by(id=user_id).one()
    return {"user": user, "errors": {}}

@view_config(route_name='admin.user.create', renderer='templates/user_form.html', request_method='GET', permission='edit')
def user_create_form(request):
    return {"user": None, "errors": {}}


@forbidden_view_config()
def custom_forbidden_view(request):
    # If the user is not authenticated, raise 401 Unauthorized
    if not request.authenticated_userid:
        return HTTPUnauthorized()
    return HTTPForbidden()
