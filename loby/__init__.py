"""This is the wsgi app to be served."""
from pyramid.config import Configurator
from pyramid.session import SignedCookieSessionFactory

def main(global_config, **settings):
    """Entry point for application."""
    my_session_factory = SignedCookieSessionFactory('itsaseekreet')
    with Configurator(settings=settings, session_factory=my_session_factory) as config:
        config.include('pyramid_tm')
        config.include('pyramid_sqlalchemy')
        config.include("pyramid_jinja2")
        config.add_jinja2_renderer('.html')
        config.add_static_view(name='static', path='loby:static')
        config.add_route('home', '/')
        config.add_route('login', '/login')
        config.scan(".views")
    return config.make_wsgi_app()
