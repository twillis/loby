"""This is the wsgi app to be served."""
from pyramid.config import Configurator
from pyramid.session import SignedCookieSessionFactory
import importlib.util


def main(global_config, **settings):
    """Entry point for application."""
    my_session_factory = SignedCookieSessionFactory("itsaseekreet")
    with Configurator(settings=settings, session_factory=my_session_factory) as config:
        config.include("pyramid_tm")
        config.include("pyramid_sqlalchemy")
        config.include("pyramid_jinja2")
        config.add_jinja2_renderer(".html")
        config.add_static_view(name="static", path="loby:static")
        config.add_route("home", "/")
        config.add_route("login", "/login")
        config.add_route("register", "/register")
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
        db_session.commit()  # Commit changes after successful seeding
        return True
    except Exception as e:
        db_session.rollback()  # Rollback in case of any errors
        print(f"An error occurred: {e}")
        return False
