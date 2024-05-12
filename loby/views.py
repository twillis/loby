from pyramid.view import view_config
from pyramid.httpexceptions import HTTPFound, HTTPUnauthorized
from pyramid_sqlalchemy import Session
from .models import User
from .schemas import LoginSchema, RegisterSchema
import colander


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
        return {"errors": e.asdict()}

    user = Session.query(User).filter_by(user_name=appstruct["username"], verified=True).first()

    if user and user.check_password(appstruct["password"]):
        request.session["user"] = user.user_name
        return HTTPFound(location=request.route_url("home"))

    return {"errors": {"login": "Invalid username or password"}}


@view_config(route_name="home", renderer="templates/home.html")
def home_view(request):
    return {}


@view_config(route_name="register", renderer="templates/register.html")
def register_view(request):
    # Assuming GET requests just show the registration form
    if request.method == "GET":
        return {}  # return empty dict if using a templating engine like Jinja2
    elif request.method == "POST":
        breakpoint()


@view_config(
    route_name="register", renderer="templates/register.html", request_method="POST"
)
def register_post_view(request):
    schema = RegisterSchema()
    try:
        # Deserialize and validate
        appstruct = schema.deserialize(request.POST)
    except colander.Invalid as e:
        return {"errors": e.asdict(), "form_data": request.POST}

    session = Session()
    user = session.query(User).filter_by(user_name=appstruct["username"]).first()
    if user:
        return {
            "errors": {"username": "Username already exists"},
            "form_data": request.POST,
        }

    new_user = User(user_name=appstruct["username"], email=appstruct["email"])
    new_user.set_password(appstruct["password"])
    session.add(new_user)
    session.commit()

    return HTTPFound(location=request.route_url("login"))
