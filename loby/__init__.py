"""This is the wsgi app to be served."""
from pyramid.config import Configurator


def main(global_config, **settings):
    """Entry point for application."""
    with Configurator(settings=settings) as config:
        config.include("pyramid_jinja2")
        config.scan()
    return config.make_wsgi_app()
