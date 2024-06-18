import json
import os
from pathlib import Path
from typing import Optional, Union, List

import aiohttp
import requests


class NoTokenFoundException(Exception):
    pass


class AuthFailedException(Exception):
    pass


class Client:
    token: str
    auth_type: str
    base_url: str
    raise_errors: bool
    session: Optional[str] = None

    def __init__(
        self, token: Optional[str] = None, base_url: Optional[str] = None, ptb: bool = False, raise_errors: bool = False
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
            base_url = "http://localhost:21723" if ptb else "http://localhost:21722"

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
        result = requests.post(f"{self.base_url}/handshake", json=data)
        response = result.json()
        session = response.get("sessionToken", None)
        if session:
            self.session = session
        else:
            raise AuthFailedException(json.dumps(response))

    def post(self, *args, **kwargs) -> bytes:
        if not self.session:
            self.renew_session()
        kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {self.session}"
        result = requests.post(*args, **kwargs)
        if self.raise_errors:
            result.raise_for_status()
        return result.content

    def get(self, *args, **kwargs) -> bytes:
        if not self.session:
            self.renew_session()
        kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {self.session}"
        result = requests.get(*args, **kwargs)
        if self.raise_errors:
            result.raise_for_status()
        return result.content

    def connection_query(self, categories: str = "*", connections: str = "*", types: str = "*") -> List[dict]:
        endpoint = f"{self.base_url}/connection/query"
        data = {"categoryFilter": categories, "connectionFilter": connections, "typeFilter": types}
        response = self.post(endpoint, json=data)
        return json.loads(response).get('found', [])

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

    def fs_blob(self, blob_data: Union[bytes, str]) -> str:
        endpoint = f"{self.base_url}/fs/blob"
        if isinstance(blob_data, str):
            blob_data = blob_data.encode('utf-8')
        response = self.post(endpoint, data=blob_data)
        return json.loads(response)["blob"]

    def fs_write(self, connection: str, blob: str, path: str):
        endpoint = f"{self.base_url}/fs/write"
        data = {
            "connection": connection,
            "blob": blob,
            "path": path
        }
        self.post(endpoint, json=data)

    def fs_script(self, connection: str, blob: str) -> str:
        endpoint = f"{self.base_url}/fs/script"
        data = {
            "connection": connection,
            "blob": blob
        }
        response = self.post(endpoint, json=data)
        return json.loads(response)["path"]


class AsyncClient(Client):
    async def renew_session(self):
        if self.auth_type == "ApiKey":
            auth = {"type": self.auth_type, "key": self.token}
        else:
            auth = {"type": self.auth_type, "authFileContent": self.token}
        data = {"auth": auth, "client": {"type": "Api", "name": "python_xpipe_client"}}

        async with aiohttp.ClientSession() as aiohttp_session:
            async with aiohttp_session.post(f"{self.base_url}/handshake", json=data) as resp:
                parsed = await resp.json(content_type=None)
        session_token = parsed.get("sessionToken", None)
        if session_token:
            self.session = session_token
        else:
            raise AuthFailedException(json.dumps(parsed))

    async def post(self, *args, **kwargs):
        if not self.session:
            await self.renew_session()
        kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {self.session}"
        async with aiohttp.ClientSession() as aiohttp_session:
            async with aiohttp_session.post(*args, **kwargs) as resp:
                if self.raise_errors:
                    resp.raise_for_status()
                return await resp.text()

    async def get(self, *args, **kwargs):
        if not self.session:
            await self.renew_session()
        kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {self.session}"
        async with aiohttp.ClientSession() as aiohttp_session:
            async with aiohttp_session.get(*args, **kwargs) as resp:
                if self.raise_errors:
                    resp.raise_for_status()
                return await resp.text()

    async def connection_query(self, categories: str = "*", connections: str = "*", types: str = "*"):
        endpoint = f"{self.base_url}/connection/query"
        data = {"categoryFilter": categories, "connectionFilter": connections, "typeFilter": types}
        response = await self.post(endpoint, json=data)
        return json.loads(response).get("found", [])

    async def shell_start(self, conn_uuid: str):
        endpoint = f"{self.base_url}/shell/start"
        data = {"connection": conn_uuid}
        response = await self.post(endpoint, json=data)
        return json.loads(response) if response else {}

    async def shell_stop(self, conn_uuid: str):
        endpoint = f"{self.base_url}/shell/stop"
        data = {"connection": conn_uuid}
        await self.post(endpoint, json=data)

    async def shell_exec(self, conn_uuid: str, command: str):
        endpoint = f"{self.base_url}/shell/exec"
        data = {"connection": conn_uuid, "command": command}
        response = await self.post(endpoint, json=data)
        return json.loads(response)

    async def fs_blob(self, blob_data: Union[bytes, str]) -> str:
        endpoint = f"{self.base_url}/fs/blob"
        if isinstance(blob_data, str):
            blob_data = blob_data.encode('utf-8')
        response = await self.post(endpoint, data=blob_data)
        return json.loads(response)["blob"]

    async def fs_write(self, connection: str, blob: str, path: str):
        endpoint = f"{self.base_url}/fs/write"
        data = {
            "connection": connection,
            "blob": blob,
            "path": path
        }
        await self.post(endpoint, json=data)

    async def fs_script(self, connection: str, blob: str) -> str:
        endpoint = f"{self.base_url}/fs/script"
        data = {
            "connection": connection,
            "blob": blob
        }
        response = await self.post(endpoint, json=data)
        return json.loads(response)["path"]