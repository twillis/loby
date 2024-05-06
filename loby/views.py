from pyramid.view import view_config
from pyramid.httpexceptions import HTTPFound
from pyramid_sqlalchemy import Session
from .models.user import User


@view_config(route_name="login", renderer="templates/login.html", request_method="GET")
def login_get_view(request):
    return {}


@view_config(route_name="login", renderer="templates/login.html", request_method="POST")
def login_post_view(request):
    username = request.params.get("username")
    password = request.params.get("password")

    user = Session.query(User).filter_by(user_name=username).first()

    if user and user.check_password(password):
        request.session["user"] = user.user_name
        return HTTPFound(location=request.route_url("home"))

    return {"error": "Invalid username or password"}


@view_config(route_name="home", renderer="templates/home.html")
def home_view(request):
    return {}
