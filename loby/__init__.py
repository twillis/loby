"""This is the wsgi app to be served."""
from pyramid.config import Configurator
from pyramid.session import SignedCookieSessionFactory
import importlib.util
from pyramid.authentication import AuthTktAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.security import Allow, Authenticated, Allowed, Denied, Everyone


class RootFactory:
    def __init__(self, request):
        self.request = request
        self.__acl__ = self.get_acl()

    def get_acl(self):
        acl = [(Allow, Everyone, 'view')]  # default to allow view to everyone if that's your policy
        from pyramid_sqlalchemy import Session
        from . import models
        session = Session()

        user_id = self.request.authenticated_userid
        if user_id:
            user_roles = session.query(models.Role).join(models.Role.users).filter(models.User.id == user_id).all()

            for role in user_roles:
                for permission in role.permissions:
                    acl.append((Allow, 'role:' + role.name, permission.name))

        return acl


class LobySecurityPolicy:
    def __init__(self, authn_policy, authz_policy):
        self.authn_policy = authn_policy
        self.authz_policy = authz_policy

    def identity(self, request):
        """Return app-specific user object."""
        from . import models
        from pyramid_sqlalchemy import Session

        userid = self.authenticated_userid(request)

        if userid is None:
            return None

        result = (
            Session.query(models.User).filter_by(id=userid, verified=True).one_or_none()
        )

        return result

    def authenticated_userid(self, request):
        return self.authn_policy.authenticated_userid(request)

    def remember(self, request, userid, **kw):
        return self.authn_policy.remember(request, userid, **kw)

    def forget(self, request):
        return self.authn_policy.forget(request)

    def permits(self, request, context, permission):
        """Allow access to everything if signed in."""

        identity = self.identity(request)

        if identity is not None:
            return Allowed("User is signed in.")

        else:
            return Denied("User is not signed in.")


def main(global_config, **settings):
    """Entry point for application."""
    sig_secret = settings.get("sig_secret", "itsaseekreet")
    session_factory = SignedCookieSessionFactory(sig_secret)
    authorization_policy = ACLAuthorizationPolicy()
    authentication_policy = AuthTktAuthenticationPolicy(sig_secret, hashalg="sha512")
    security_policy = LobySecurityPolicy(authentication_policy, authorization_policy)
    with Configurator(
        settings=settings,
        session_factory=session_factory,
        root_factory=RootFactory,
        # authorization_policy=authorization_policy,
        # authentication_policy=authentication_policy,
        security_policy=security_policy,
    ) as config:
        config.include("pyramid_tm")
        config.include("pyramid_sqlalchemy")
        config.include("pyramid_jinja2")
        config.add_jinja2_renderer(".html")
        config.add_static_view(name="static", path="loby:static")
        config.add_route("home", "/")
        config.add_route("login", "/login")
        config.add_route("register", "/register")
        config.add_route("admin.user", "/admin/user")
        config.add_route("admin.user.create", "/admin/user/create")
        config.add_route("admin.user.edit", "/admin/user/{user_id}")
        config.add_route("admin.user.save", "/admin/user/{user_id}/save")
        config.scan(".views")
    return config.make_wsgi_app()


def execute_seed_script(script_path, db_session):
    """
    Executes a seeding script, which contains a seed(session) function.

    Args:
        script_path (str): The file path to the seeding script.
        db_session (Session): An instance of SQLAlchemy Session to pass to the seed function.

    Returns:
        bool: True if the seed script executed successfully, False otherwise.
    """
    spec = importlib.util.spec_from_file_location("seed_module", script_path)
    seed_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(seed_module)

    try:
        seed_module.seed(db_session)
        db_session.flush()  # Commit changes after successful seeding
        return True
    except Exception as exc:
        raise Exception(f"error running {script_path}. \n {exc}")
