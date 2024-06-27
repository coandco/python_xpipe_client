import json
import logging
import os
import uuid
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO, List, Optional, Union

import aiohttp.web_response
import requests
from aiohttp import ClientResponseError
from aiohttp_requests import requests as async_requests
from packaging.version import Version

from .exceptions import AuthFailedException, NoTokenFoundException, error_code_map

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class Client:
    token: str
    auth_type: str
    base_url: str
    raise_errors: bool
    session: Optional[str] = None
    min_version: Version = Version("10.0-22")

    def __init__(
        self, token: Optional[str] = None, base_url: Optional[str] = None, ptb: bool = False, raise_errors: bool = True
    ):
        auth_type = "ApiKey"
        # Try getting the auth from the local filesystem if none is provided
        if not token:
            try:
                auth_type = "Local"
                auth_file = Path(os.getenv("TEMP", "/tmp")) / "xpipe_auth"
                token = auth_file.read_text().strip()
            except Exception as e:
                raise NoTokenFoundException(f"No auth provided and couldn't load xpipe_auth: {e!r}")

        if not base_url:
            base_url = "http://127.0.0.1:21722" if ptb else "http://127.0.0.1:21721"

        self.token = token
        self.auth_type = auth_type
        self.base_url = base_url.strip("/")
        self.raise_errors = raise_errors

    def renew_session(self):
        if self.auth_type == "ApiKey":
            auth = {"type": self.auth_type, "key": self.token}
        else:
            auth = {"type": self.auth_type, "authFileContent": self.token}
        data = {"auth": auth, "client": {"type": "Api", "name": "python_xpipe_client"}}
        req_id = str(uuid.uuid4())
        logger.debug(f"[{req_id}] {self.base_url}/handshake POST with args {data}")
        result = requests.post(f"{self.base_url}/handshake", json=data)
        logger.debug(f"[{req_id}] Response: {result.content}")
        response = result.json()
        session = response.get("sessionToken", None)
        if session:
            self.session = session
        else:
            raise AuthFailedException(json.dumps(response))
        assert (
            Version(self.daemon_version()["version"]) >= self.min_version
        ), f"xpipe_client requires XPipe of at least {self.min_version}"

    def _post(self, *args, req_id: Optional[str] = None, **kwargs) -> requests.Response:
        if not self.session:
            self.renew_session()

        if not req_id:
            req_id = str(uuid.uuid4())
        url = args[0]
        data = kwargs.get("json", {})
        logger.debug(f"[{req_id}] {url} POST with args {data}")

        kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {self.session}"
        resp: requests.Response = requests.post(*args, **kwargs)
        status_code, reason = resp.status_code, error_code_map.get(resp.status_code, "Unknown Code")
        if self.raise_errors and status_code >= 400:
            message = f"{status_code} {reason} for url: {resp.url}"
            # Attempt to enrich the message with the parsed reason
            if status_code == 400:
                with suppress(Exception):
                    message = f'Client Error for {resp.url}: {resp.json()["message"]}'
            elif status_code == 500:
                with suppress(Exception):
                    message = f'Server Error for {resp.url}: {resp.json()["error"]["message"]}'
            raise requests.HTTPError(message, response=resp)
        return resp

    def post(self, *args, **kwargs) -> bytes:
        req_id = uuid.uuid4()
        resp = self._post(*args, req_id=str(req_id), **kwargs)
        logger.debug(f"[{req_id}] Response: {resp.content[:4096]}")
        return resp.content

    def _get(self, *args, req_id: Optional[str] = None, **kwargs) -> requests.Response:
        if not self.session:
            self.renew_session()

        if not req_id:
            req_id = str(uuid.uuid4())
        url = args[0]
        data = kwargs.get("json", {})
        logger.debug(f"[{req_id}] {url} GET with args {data}")

        kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {self.session}"
        resp = requests.get(*args, **kwargs)
        status_code, reason = resp.status_code, error_code_map.get(resp.status_code, "Unknown Code")
        if self.raise_errors and status_code >= 400:
            message = f"{status_code} {reason} for url: {resp.url}"
            # Attempt to enrich the message with the parsed reason
            if status_code == 400:
                try:
                    message = f'Client Error for {resp.url}: {resp.json()["message"]}'
                except Exception:
                    pass
            elif status_code == 500:
                try:
                    message = f'Server Error for {resp.url}: {resp.json()["error"]["message"]}'
                except Exception:
                    pass
            raise requests.HTTPError(message, response=resp)
        return resp

    def get(self, *args, **kwargs) -> bytes:
        req_id = uuid.uuid4()
        resp = self._get(*args, **kwargs)
        logger.debug(f"[{req_id}] Response: {resp.content[:4096]}")
        return resp.content

    def connection_query(self, categories: str = "*", connections: str = "*", types: str = "*") -> List[str]:
        endpoint = f"{self.base_url}/connection/query"
        data = {"categoryFilter": categories, "connectionFilter": connections, "typeFilter": types}
        response = self.post(endpoint, json=data)
        return json.loads(response).get("found", [])

    def connection_info(self, uuids: Union[str, List[str]]) -> List[dict]:
        endpoint = f"{self.base_url}/connection/info"
        # If we're passed a single UUID, wrap it in a list like the API expects
        if not isinstance(uuids, list):
            uuids = [uuids]
        data = {"connections": uuids}
        response = self.post(endpoint, json=data)
        return json.loads(response).get("infos", [])

    def get_connections(self, categories: str = "*", connections: str = "*", types: str = "*") -> List[dict]:
        """Convenience method to chain connection/query with connection/info"""
        uuids = self.connection_query(categories, connections, types)
        return self.connection_info(uuids) if uuids else []

    def daemon_version(self) -> dict:
        endpoint = f"{self.base_url}/daemon/version"
        response = self.get(endpoint)
        return json.loads(response)

    def shell_start(self, conn_uuid: str) -> dict:
        endpoint = f"{self.base_url}/shell/start"
        data = {"connection": conn_uuid}
        response = self.post(endpoint, json=data)
        return json.loads(response) if response else {}

    def shell_stop(self, conn_uuid: str):
        endpoint = f"{self.base_url}/shell/stop"
        data = {"connection": conn_uuid}
        self.post(endpoint, json=data)

    def shell_exec(self, conn_uuid: str, command: str) -> dict:
        endpoint = f"{self.base_url}/shell/exec"
        data = {"connection": conn_uuid, "command": command}
        response = self.post(endpoint, json=data)
        return json.loads(response) if response else {}

    def fs_blob(self, blob_data: Union[bytes, str, BinaryIO]) -> str:
        endpoint = f"{self.base_url}/fs/blob"
        if isinstance(blob_data, str):
            blob_data = blob_data.encode("utf-8")
        response = self.post(endpoint, data=blob_data)
        return json.loads(response)["blob"]

    def fs_write(self, connection: str, blob: str, path: str):
        endpoint = f"{self.base_url}/fs/write"
        data = {"connection": connection, "blob": blob, "path": path}
        self.post(endpoint, json=data)

    def fs_script(self, connection: str, blob: str) -> str:
        endpoint = f"{self.base_url}/fs/script"
        data = {"connection": connection, "blob": blob}
        response = self.post(endpoint, json=data)
        return json.loads(response)["path"]

    def _fs_read(self, connection: str, path: str) -> requests.Response:
        # Internal version of the function that returns the raw response object
        # Here so clients can do things like stream the response to disk if it's a big file
        endpoint = f"{self.base_url}/fs/read"
        data = {"connection": connection, "path": path}
        return self._post(endpoint, json=data, stream=True)

    def fs_read(self, connection: str, path: str) -> bytes:
        return self._fs_read(connection, path).content


class AsyncClient(Client):
    @classmethod
    def from_sync_client(cls, sync: Client) -> "AsyncClient":
        async_client = cls(token=sync.token, base_url=sync.base_url, raise_errors=sync.raise_errors)
        async_client.auth_type = sync.auth_type
        async_client.session = sync.session
        return async_client

    async def renew_session(self):
        if self.auth_type == "ApiKey":
            auth = {"type": self.auth_type, "key": self.token}
        else:
            auth = {"type": self.auth_type, "authFileContent": self.token}
        data = {"auth": auth, "client": {"type": "Api", "name": "python_xpipe_client"}}
        req_id = str(uuid.uuid4())
        logger.debug(f"[{req_id}] {self.base_url}/handshake POST with args {data}")
        resp = await async_requests.post(f"{self.base_url}/handshake", json=data)
        logger.debug(f"[{req_id}] Response: {await resp.read()}")
        parsed = await resp.json(content_type=None)
        session_token = parsed.get("sessionToken", None)
        if session_token:
            self.session = session_token
        else:
            raise AuthFailedException(json.dumps(parsed))
        assert (
            Version((await self.daemon_version())["version"]) >= self.min_version
        ), f"xpipe_client requires XPipe of at least {self.min_version}"

    async def _post(self, *args, req_id: Optional[str] = None, **kwargs) -> aiohttp.ClientResponse:
        if not self.session:
            await self.renew_session()

        if not req_id:
            req_id = str(uuid.uuid4())
        url = args[0]
        data = kwargs.get("json", {})
        logger.debug(f"[{req_id}] {url} POST with args {data}")

        kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {self.session}"
        resp = await async_requests.post(*args, **kwargs)
        if self.raise_errors and not resp.ok:
            status_code, reason = resp.status, error_code_map.get(resp.status, "Unknown Code")
            message = f"{status_code} {reason} for url: {resp.url}"
            # Attempt to enrich the message with the parsed reason
            text = await resp.text()
            if status_code == 400:
                with suppress(Exception):
                    message = f'Client Error: {json.loads(text)["message"]}'
            elif status_code == 500:
                with suppress(Exception):
                    message = f'Server Error: {json.loads(text)["error"]["message"]}'
            raise ClientResponseError(
                resp.request_info,
                resp.history,
                status=resp.status,
                message=message,
                headers=resp.headers,
            )
        return resp

    async def post(self, *args, **kwargs) -> bytes:
        req_id = uuid.uuid4()
        resp = await self._post(*args, req_id=str(req_id), **kwargs)
        content = await resp.read()
        logger.debug(f"[{req_id}] Response: {content[:4096]}")
        return content

    async def _get(self, *args, req_id: Optional[str] = None, **kwargs) -> aiohttp.ClientResponse:
        if not self.session:
            await self.renew_session()

        if not req_id:
            req_id = str(uuid.uuid4())
        url = args[0]
        data = kwargs.get("json", {})
        logger.debug(f"[{req_id}] {url} GET with args {data}")

        kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {self.session}"
        resp = await async_requests.get(*args, **kwargs)
        if self.raise_errors and not resp.ok:
            status_code, reason = resp.status, error_code_map.get(resp.status, "Unknown Code")
            message = f"{status_code} {reason} for url: {resp.url}"
            # Attempt to enrich the message with the parsed reason
            text = await resp.text()
            if status_code == 400:
                with suppress(Exception):
                    message = f'Client Error for {resp.url}: {json.loads(text)["message"]}'
            elif status_code == 500:
                with suppress(Exception):
                    message = f'Server Error for {resp.url}: {json.loads(text)["error"]["message"]}'
            raise ClientResponseError(
                resp.request_info,
                resp.history,
                status=resp.status,
                message=message,
                headers=resp.headers,
            )
        return resp

    async def get(self, *args, **kwargs) -> bytes:
        req_id = uuid.uuid4()
        resp = await self._get(*args, req_id=str(req_id), **kwargs)
        content = await resp.read()
        logger.debug(f"[{req_id}] Response: {content[:4096]}")
        return content

    async def connection_query(self, categories: str = "*", connections: str = "*", types: str = "*") -> List[str]:
        endpoint = f"{self.base_url}/connection/query"
        data = {"categoryFilter": categories, "connectionFilter": connections, "typeFilter": types}
        response = await self.post(endpoint, json=data)
        return json.loads(response).get("found", [])

    async def connection_info(self, uuids: Union[str, List[str]]) -> List[dict]:
        endpoint = f"{self.base_url}/connection/info"
        # If we're passed a single UUID, wrap it in a list like the API expects
        if not isinstance(uuids, list):
            uuids = [uuids]
        data = {"connections": uuids}
        response = await self.post(endpoint, json=data)
        return json.loads(response).get("infos", [])

    async def get_connections(self, categories: str = "*", connections: str = "*", types: str = "*") -> List[dict]:
        uuids = await self.connection_query(categories, connections, types)
        return (await self.connection_info(uuids)) if uuids else []

    async def daemon_version(self) -> dict:
        endpoint = f"{self.base_url}/daemon/version"
        response = await self.get(endpoint)
        return json.loads(response)

    async def shell_start(self, conn_uuid: str) -> dict:
        endpoint = f"{self.base_url}/shell/start"
        data = {"connection": conn_uuid}
        response = await self.post(endpoint, json=data)
        return json.loads(response) if response else {}

    async def shell_stop(self, conn_uuid: str):
        endpoint = f"{self.base_url}/shell/stop"
        data = {"connection": conn_uuid}
        await self.post(endpoint, json=data)

    async def shell_exec(self, conn_uuid: str, command: str) -> dict:
        endpoint = f"{self.base_url}/shell/exec"
        data = {"connection": conn_uuid, "command": command}
        response = await self.post(endpoint, json=data)
        return json.loads(response)

    async def fs_blob(self, blob_data: Union[bytes, str]) -> str:
        endpoint = f"{self.base_url}/fs/blob"
        if isinstance(blob_data, str):
            blob_data = blob_data.encode("utf-8")
        response = await self.post(endpoint, data=blob_data)
        return json.loads(response)["blob"]

    async def fs_write(self, connection: str, blob: str, path: str):
        endpoint = f"{self.base_url}/fs/write"
        data = {"connection": connection, "blob": blob, "path": path}
        await self.post(endpoint, json=data)

    async def fs_script(self, connection: str, blob: str) -> str:
        endpoint = f"{self.base_url}/fs/script"
        data = {"connection": connection, "blob": blob}
        response = await self.post(endpoint, json=data)
        return json.loads(response)["path"]

    async def _fs_read(self, connection: str, path: str) -> aiohttp.ClientResponse:
        # Internal version of the function that returns the raw response object
        # Here so clients can do things like stream the response to disk if it's a big file
        endpoint = f"{self.base_url}/fs/read"
        data = {"connection": connection, "path": path}
        resp = await self._post(endpoint, json=data)
        return resp

    async def fs_read(self, connection: str, path: str) -> bytes:
        resp = await self._fs_read(connection, path)
        return await resp.read()
