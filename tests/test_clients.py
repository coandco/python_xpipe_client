import pytest
import os
from pathlib import Path
from xpipe_client.clients import Client, AsyncClient


@pytest.fixture
def sync_local_client():
    return Client(raise_errors=True)


@pytest.fixture
async def async_local_client():
    async with AsyncClient(raise_errors=True) as async_client:
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
    response = sync_local_client.shell_start(local_connection)
    assert set(response.keys()) == {"shellDialect", "osType", "osName", "temp"}


async def test_async_shell_start(async_local_client: AsyncClient):
    connections = await async_local_client.connection_query(connections="")
    local_connection = connections[0]["connection"]
    response = await async_local_client.shell_start(local_connection)
    assert set(response.keys()) == {"shellDialect", "osType", "osName", "temp"}


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


def test_fs_blob(sync_local_client: Client):
    blob_id = sync_local_client.fs_blob("test")
    assert blob_id


async def test_async_fs_blob(async_local_client: AsyncClient):
    blob = await async_local_client.fs_blob("test")
    assert blob


def test_fs_write(sync_local_client: Client):
    connection = sync_local_client.connection_query(connections="")[0]["connection"]
    blob = sync_local_client.fs_blob("test")
    system_info = sync_local_client.shell_start(connection)
    testfile_path = Path(system_info["temp"]) / "xpipe_testfile"
    sync_local_client.fs_write(connection, blob, str(testfile_path.resolve()))
    sync_local_client.shell_stop(connection)
    assert testfile_path.read_text() == "test"
    testfile_path.unlink(missing_ok=True)


async def test_async_fs_write(async_local_client: AsyncClient):
    connection = (await async_local_client.connection_query(connections=""))[0]["connection"]
    blob = await async_local_client.fs_blob("test")
    system_info = await async_local_client.shell_start(connection)
    testfile_path = Path(system_info["temp"]) / "xpipe_testfile"
    await async_local_client.fs_write(connection, blob, str(testfile_path.resolve()))
    await async_local_client.shell_stop(connection)
    assert testfile_path.read_text() == "test"
    testfile_path.unlink(missing_ok=True)


def test_fs_script(sync_local_client: Client):
    connection = sync_local_client.connection_query(connections="")[0]["connection"]
    system_info = sync_local_client.shell_start(connection)
    if system_info["osType"] == "Windows":
        script = "@echo off\necho hello world"
    else:
        script = "#!/bin/sh\necho hello world"
    blob = sync_local_client.fs_blob(script)
    script_path = sync_local_client.fs_script(connection, blob)
    assert Path(script_path).read_text() == script
    output = sync_local_client.shell_exec(connection, f'"{script_path}"')
    assert output["stdout"].strip() == "hello world"
    sync_local_client.shell_stop(connection)
    Path(script_path).unlink(missing_ok=True)


async def test_async_fs_script(async_local_client: AsyncClient):
    connection = (await async_local_client.connection_query(connections=""))[0]["connection"]
    system_info = await async_local_client.shell_start(connection)
    if system_info["osType"] == "Windows":
        script = "@echo off\necho hello world"
    else:
        script = "#!/bin/sh\necho hello world"
    blob = await async_local_client.fs_blob(script)
    script_path = await async_local_client.fs_script(connection, blob)
    assert Path(script_path).read_text() == script
    output = await async_local_client.shell_exec(connection, f'"{script_path}"')
    assert output["stdout"].strip() == "hello world"
    await async_local_client.shell_stop(connection)
    Path(script_path).unlink(missing_ok=True)


