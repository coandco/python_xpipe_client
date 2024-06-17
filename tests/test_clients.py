import pytest
import os
from xpipe_client.clients import Client, AsyncClient


@pytest.fixture
def sync_local_client():
    return Client()


@pytest.fixture
async def async_local_client():
    async with AsyncClient() as async_client:
        yield async_client


def test_sync_local_login(sync_local_client: Client):
    assert sync_local_client.session is None
    sync_local_client.renew_session()
    assert sync_local_client.session is not None


async def test_async_local_login(async_local_client: AsyncClient):
    assert async_local_client.session is None
    await async_local_client.renew_session()
    assert async_local_client.session is not None


def test_sync_apikey_login():
    apikey = os.environ.get("XPIPE_APIKEY", None)
    assert apikey is not None
    client = Client(token=apikey)
    assert client.session is None
    client.renew_session()
    assert client.session is not None


async def test_async_apikey_login():
    apikey = os.environ.get("XPIPE_APIKEY", None)
    assert apikey is not None
    client = AsyncClient(token=apikey)
    assert client.session is None
    await client.renew_session()
    assert client.session is not None


def test_connection_query(sync_local_client: Client):
    connections = sync_local_client.connection_query(connections="")
    assert len(connections) > 0
    assert connections[0].get("connection", None) is not None


async def test_async_connection_query(async_local_client: AsyncClient):
    connections = await async_local_client.connection_query(connections="")
    assert len(connections) > 0
    assert connections[0].get("connection", None) is not None


def test_shell_start(sync_local_client: Client):
    local_connection = sync_local_client.connection_query(connections="")[0]["connection"]
    sync_local_client.shell_start(local_connection)


async def test_async_shell_start(async_local_client: AsyncClient):
    connections = await async_local_client.connection_query(connections="")
    local_connection = connections[0]["connection"]
    await async_local_client.shell_start(local_connection)


def test_shell_stop(sync_local_client: Client):
    local_connection = sync_local_client.connection_query(connections="")[0]["connection"]
    sync_local_client.shell_start(local_connection)
    sync_local_client.shell_stop(local_connection)


async def test_async_shell_stop(async_local_client: AsyncClient):
    connections = await async_local_client.connection_query(connections="")
    local_connection = connections[0]["connection"]
    await async_local_client.shell_start(local_connection)
    await async_local_client.shell_stop(local_connection)


def test_shell_exec(sync_local_client: Client):
    local_connection = sync_local_client.connection_query(connections="")[0]["connection"]
    sync_local_client.shell_start(local_connection)
    retval = sync_local_client.shell_exec(local_connection, "echo hello world")
    assert retval == {'exitCode': 0, "stdout": "hello world", "stderr": ""}
    sync_local_client.shell_stop(local_connection)


async def test_async_shell_exec(async_local_client: AsyncClient):
    local_connection = (await async_local_client.connection_query(connections=""))[0]["connection"]
    await async_local_client.shell_start(local_connection)
    retval = await async_local_client.shell_exec(local_connection, "echo hello world")
    assert retval == {'exitCode': 0, "stdout": "hello world", "stderr": ""}
    await async_local_client.shell_stop(local_connection)
