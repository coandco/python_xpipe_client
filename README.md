# xpipe_client
[![GitHub license](https://img.shields.io/github/license/coandco/python_xpipe_client.svg)](https://github.com/coandco/python_xpipe_client/blob/master/LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/xpipe_client)](https://pypi.org/project/xpipe_client/)

Python client for the XPipe API


## Installation
```
python3 -m pip install xpipe_client
```

## Usage

```python
from xpipe_client import Client

# By default, Client() will read the API key from xpipe_auth on the local filesystem
# and talk to the XPipe API on localhost.  To connect to a remote instance with an API
# key, use Client(token="foo", base_url = "http://servername:21723")
client = Client()

# connection_query accepts glob-based filters on the category, connection name, and connection type
all_connections = client.connection_query()

# Each connection includes uuid, category, connection, and type information
first_connection_uuid = all_connections[0]["uuid"]

# Before any shell commands can be run, a shell session must be started on a connection
client.shell_start(first_connection_uuid)

# Prints {'exitCode': 0, 'stdout': 'hello world', 'stderr': ''}
print(client.shell_exec(first_connection_uuid, "echo hello world"))

# Clean up after ourselves
client.shell_stop(first_connection_uuid)
```

There's also an async version of the client that can be accessed as AsyncClient:
```python
import asyncio
from xpipe_client import AsyncClient


async def main():
    # By default, AsyncClient() will read the API key from xpipe_auth on the local filesystem
    # and talk to the XPipe API on localhost.  To connect to a remote instance with an API
    # key, use Client(token="foo", base_url = "http://servername:21723")
    client = AsyncClient()

    # connection_query accepts glob-based filters on the category, connection name, and connection type
    all_connections = await client.connection_query()
    
    # Each connection includes uuid, category, connection, and type information
    first_connection_uuid = all_connections[0]["uuid"]
    
    # Before any shell commands can be run, a shell session must be started on a connection
    await client.shell_start(first_connection_uuid)
    
    # Prints {'exitCode': 0, 'stdout': 'hello world', 'stderr': ''}
    print(await client.shell_exec(first_connection_uuid, "echo hello world"))
    
    # Clean up after ourselves
    await client.shell_stop(first_connection_uuid)


if __name__ == "__main__":
    asyncio.run(main())
```
