# Smart Device Client

This is a package meant to facilitate writing clients for the calibre wireless device connection. It is also mostly a learning excercise on my part to get my head around the protocol to talk to calibre as a wireless device.

Implementation heavily inspired by the `calibre.koplugin` plugin in [koreader](https://github.com/koreader/koreader).

## Usage

```python
from smart_device_client import SmartDeviceClient, SmartDeviceOpcode
import shutil

import logging
logging.basicConfig(level=logging.DEBUG)

# Inherit from SmartDeviceClient
class MySmartDeviceClient(SmartDeviceClient):
    # Implement methods according to your environment
    def on_free_space(self, message):
        _, _, free = shutil.disk_usage("/")
        # Return the mesages that should be sent
        return (SmartDeviceOpcode.OK, {"free_space_on_device": free})

    ...

# Init the client (or do it manually providing a host and port)
client = MySmartDeviceClient.find_calibre_server()
# And serve
client.serve()
```
