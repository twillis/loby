import alembic
import alembic.config
import alembic.command
import os
from pyramid.paster import get_appsettings
from pyramid.scripting import prepare
from pyramid.testing import DummyRequest, testConfig
import pytest
import transaction
import webtest

from loby import main, execute_seed_script
from loby import models
import pyramid_sqlalchemy
Base = pyramid_sqlalchemy.BaseObject


def pytest_addoption(parser):
    parser.addoption("--ini", action="store", metavar="INI_FILE")


@pytest.fixture(scope="session")
def ini_file(request):
    # potentially grab this path from a pytest option
    return os.path.abspath(request.config.option.ini or "testing.ini")


@pytest.fixture(scope="session")
def app_settings(ini_file):
    return get_appsettings(ini_file)


@pytest.fixture(scope="session")
def sqlalchemy_url(app_settings):
    breakpoint()
    return app_settings.get("sqlalchemy.url", pyramid_sqlalchemy.fixtures.DEFAULT_URI)


@pytest.fixture(scope="session")
def dbengine(app_settings, ini_file):
    engine = pyramid_sqlalchemy.engine_from_config(app_settings)
    alembic_cfg = alembic.config.Config(ini_file)
    Base.metadata.drop_all(bind=engine)
    alembic.command.stamp(alembic_cfg, None, purge=True)

    # run migrations to initialize the database
    # depending on how we want to initialize the database from scratch
    # we could alternatively call:
    # Base.metadata.create_all(bind=engine)
    # alembic.command.stamp(alembic_cfg, "head")
    alembic.command.upgrade(alembic_cfg, "head")

    yield engine

    Base.metadata.drop_all(bind=engine)
    alembic.command.stamp(alembic_cfg, None, purge=True)


@pytest.fixture(scope="session")
def app(app_settings, dbengine):
    return main({}, dbengine=dbengine, **app_settings)

@pytest.fixture
def tm():
    tm = transaction.TransactionManager(explicit=True)
    tm.begin()
    tm.doom()

    yield tm

    tm.abort()


@pytest.fixture
def dbsession(dbengine, sql_session):
    return sql_session

@pytest.fixture
def core_seeds(dbsession):
    files = [
        './seeds/admin_user_admin_role.py'
    ]

    for f in files:
        execute_seed_script(f, dbsession)

@pytest.fixture
def test_app(app, tm, dbsession, core_seeds):
    # override request.dbsession and request.tm with our own
    # externally-controlled values that are shared across requests but aborted
    # at the end
    testapp = webtest.TestApp(
        app,
        extra_environ={
            "HTTP_HOST": "example.com",
            "tm.active": True,
            "tm.manager": tm,
            "app.dbsession": dbsession,
        },
    )

    return testapp


@pytest.fixture
def app_request(app, tm, dbsession):
    """
    A real request.

    This request is almost identical to a real request but it has some
    drawbacks in tests as it's harder to mock data and is heavier.

    """
    with prepare(registry=app.registry) as env:
        request = env["request"]
        request.host = "example.com"

        # without this, request.dbsession will be joined to the same transaction
        # manager but it will be using a different sqlalchemy.orm.Session using
        # a separate database transaction
        request.dbsession = dbsession
        request.tm = tm

        yield request


@pytest.fixture
def dummy_request(tm, dbsession):
    """
    A lightweight dummy request.

    This request is ultra-lightweight and should be used only when the request
    itself is not a large focus in the call-stack.  It is much easier to mock
    and control side-effects using this object, however:

    - It does not have request extensions applied.
    - Threadlocals are not properly pushed.

    """
    request = DummyRequest()
    request.host = "example.com"
    request.dbsession = dbsession
    request.tm = tm

    return request


@pytest.fixture
def dummy_config(dummy_request):
    """
    A dummy :class:`pyramid.config.Configurator` object.  This allows for
    mock configuration, including configuration for ``dummy_request``, as well
    as pushing the appropriate threadlocals.

    """
    with testConfig(request=dummy_request) as config:
        yield config
