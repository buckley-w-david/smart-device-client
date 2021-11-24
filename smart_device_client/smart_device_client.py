from enum import IntEnum
import json
import logging
import re
import socket
from typing import Tuple, Optional, Callable, Dict

import zmq

RESP_PATTERN = re.compile(r"calibre wireless device client \(on (.+)\);(\d+),(\d+)")
CALIBRE_MESSAGE = re.compile(r"^(?P<length>\d+)(?P<message>.*)")
MAGIC_PATH_LENGTH = 37

Port = int
Address = str
Host = Tuple[Address, Port]
CalibrePayload = Dict

# mapping copied directly from src/calibre/devices/smart_device_app/driver.py in calibre repo
class SmartDeviceOpcode(IntEnum):
    NOOP = 12
    OK = 0
    BOOK_DONE = 11
    CALIBRE_BUSY = 18
    SET_LIBRARY_INFO = 19
    DELETE_BOOK = 13
    DISPLAY_MESSAGE = 17
    ERROR = 20
    FREE_SPACE = 5
    GET_BOOK_FILE_SEGMENT = 14
    GET_BOOK_METADATA = 15
    GET_BOOK_COUNT = 6
    GET_DEVICE_INFORMATION = 3
    GET_INITIALIZATION_INFO = 9
    SEND_BOOKLISTS = 7
    SEND_BOOK = 8
    SEND_BOOK_METADATA = 16
    SET_CALIBRE_DEVICE_INFO = 1
    SET_CALIBRE_DEVICE_NAME = 2
    TOTAL_SPACE = 4

ResponsePayload = Tuple[SmartDeviceOpcode, Dict]
WirelessCallback = Callable[['SmartDeviceClient', SmartDeviceOpcode, CalibrePayload], Optional[ResponsePayload]]
ImplementationMap = Dict[SmartDeviceOpcode, WirelessCallback]

CLIENT_NAME = 'smart-device-client'
DEVICE = 'Kobo'
DEVICE_NAME = f"{CLIENT_NAME} ({DEVICE})"
VERSION = '0.1.0'
VALID_EXTENSIONS = ['epub']

logger = logging.getLogger(__name__)

# TODO: Configuration
# appName
# deviceKind
# deviceName (handled by the last two)
# version
# extensions

class SmartDeviceClient:
    COMPANION_LOCAL_PORT = 8134

    def __init__(self, calibre_host: Host, replied_port: Port):
        self.calibre_host = calibre_host
        self.replied_port = replied_port
        self.implementation: ImplementationMap = {
            SmartDeviceOpcode.GET_INITIALIZATION_INFO: SmartDeviceClient._get_init_info,
            SmartDeviceOpcode.GET_DEVICE_INFORMATION: SmartDeviceClient._get_device_info,
            SmartDeviceOpcode.SET_CALIBRE_DEVICE_INFO: SmartDeviceClient._set_calibre_info,
            SmartDeviceOpcode.FREE_SPACE: SmartDeviceClient._get_free_space,
            SmartDeviceOpcode.SET_LIBRARY_INFO: SmartDeviceClient._set_calibre_info,
            SmartDeviceOpcode.GET_BOOK_COUNT: SmartDeviceClient._get_book_count,
            SmartDeviceOpcode.NOOP: SmartDeviceClient._noop,
        }

    def _get_init_info(self, opcode: SmartDeviceOpcode, info: CalibrePayload) -> ResponsePayload:
        # TODO: I'm not using this for anything at the moment, but I could
        calibre_version = '.'.join(map(str, info['calibre_version']))

        # TODO: handle auth
        # local getPasswordHash = function()
        #     local password = G_reader_settings:readSetting("calibre_wireless_password")
        #     local challenge = arg.passwordChallenge
        #     if password and challenge then
        #         return sha.sha1(password..challenge)
        #     else
        #         return ""
        #     end
        # 

        # TODO: Looks like we're going toh ave to formalize some configuration spec
        init_info = {
            'appName': CLIENT_NAME, # TODO: Configurable
            'acceptedExtensions': VALID_EXTENSIONS, # TODO: Configurable
            'cacheUsesLpaths': True,
            'canAcceptLibraryInfo': True,
            'canDeleteMultipleBooks': True,
            'canReceiveBookBinary': True,
            'canSendOkToSendbook': True,
            'canStreamBooks': True,
            'canStreamMetadata': True,
            'canUseCachedMetadata': True,
            'ccVersionNumber': VERSION,
            'coverHeight': 240,
            'deviceKind': DEVICE, # TODO: Configurable
            'deviceName': DEVICE_NAME, # TODO Configurable
            'extensionPathLengths': [MAGIC_PATH_LENGTH for _ in VALID_EXTENSIONS],
            'passwordHash': "", # TODO: getPasswordHash()
            'maxBookContentPacketLen': 4096,
            'useUuidFileNames': False,
            'versionOK': True,
        }
        return (SmartDeviceOpcode.OK, init_info)

    def _get_device_info(self, opcode: SmartDeviceOpcode, info: CalibrePayload) -> ResponsePayload:
        return (SmartDeviceOpcode.OK, {
            'device_info': {
               # 'device_store_uuid' = CalibreMetadata.drive.device_store_uuid,
               'device_name': DEVICE_NAME,
            },
            'version': VERSION,
            'device_version': VERSION,
        })

    def _set_calibre_info(self, opcode: SmartDeviceOpcode, info: CalibrePayload) -> ResponsePayload:
        self.device_info = info
        return (SmartDeviceOpcode.OK, {})

    def _get_free_space(self, opcode: SmartDeviceOpcode, info: CalibrePayload) -> ResponsePayload:
        logger.warning("You need to register a FREE_SPACE handler")
        return (SmartDeviceOpcode.OK, {"free_space_on_device": 1024 * 1024 * 1024})

    def _set_library_info(self, opcode: SmartDeviceOpcode, info: CalibrePayload) -> ResponsePayload:
        logger.warning("You may want to register a SET_LIBRARY_INFO handler")
        return (SmartDeviceOpcode.OK, {})

    def _get_book_count(self, opcode: SmartDeviceOpcode, info: CalibrePayload) -> ResponsePayload:
        logger.warning("You need to register a GET_BOOK_COUNT handler")
        return (SmartDeviceOpcode.OK, { "willStream": True, "willScan": True, "count": 0, })

    def _noop(self, opcode: SmartDeviceOpcode, info: CalibrePayload) -> None:
        logger.debug("received %s with %s", opcode, info)

    def _unimplemented(self, opcode: SmartDeviceOpcode, payload: CalibrePayload) -> None:
        logger.warning("received %s, which is is unimplemented. %s", opcode, payload)

    def _send(self, response: ResponsePayload) -> None:
        opcode, payload = response
        message = json.dumps([opcode.value, payload])
        # calibre exchanges these messages in this format:
        # LENGTH[OPCODE, MESSAGE]
        # Where LENGTH is for the array holding the opcode and message
        encoded = (str(len(message)) +  message).encode()
        self.socket.send_multipart([self.id, encoded])

    def register(self, opcode: SmartDeviceOpcode, action: WirelessCallback):
        self.implementation[opcode] = action

    def start(self):
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.STREAM)
        self.socket.connect("tcp://%s:%d" % (self.calibre_host[0], self.replied_port))
        self.id = self.socket.getsockopt(zmq.IDENTITY)
        poller = zmq.Poller()
        poller.register(self.socket, zmq.POLLIN)

        while True:
            socks = dict(poller.poll())

            if socks.get(self.socket) == zmq.POLLIN:
                buffer = []
                cl = 0
                _ = self.socket.recv() # This is weird... We always get this ID value first that we don't need
                message = self.socket.recv().decode('utf-8') 
                # regex is probably overkill for this parsing now that I've realized I can't just consume the whole message in one big recv
                if match := CALIBRE_MESSAGE.match(message):
                    length = int(match.group("length"))
                    message = match.group("message")
                    buffer.append(message)
                    cl += len(message)

                    # If the payload is too big, we have to do those 2 recv calls in a loop until we've read in everything that was sent
                    while cl < length:
                        _ = self.socket.recv()
                        message = self.socket.recv().decode('utf-8') 
                        buffer.append(message)
                        cl += len(message)
                    full_message = ''.join(buffer)
                    logger.debug(full_message)

                    op, payload = json.loads(full_message)

                    opcode = SmartDeviceOpcode(op)
                    implementation = self.implementation.get(opcode) or SmartDeviceClient._unimplemented

                    ret = implementation(self, opcode, payload)
                    if ret:
                        self._send(ret)

    def close(self):
        try:
            self.socket.close()
            self.context.term()
        except Exception as e:
            logger.exception(e)

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @staticmethod
    def zeroconf_client() -> Optional["SmartDeviceClient"]:  # type: ignore
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(5)

        broadcast_ports = [54982, 48123, 39001, 44044, 59678]
        try:
            for port in broadcast_ports:
                count = sock.sendto(b"hello", (b"255.255.255.255", port))
                if count:
                    dgram, host = sock.recvfrom(1024)
                    if match := RESP_PATTERN.match(dgram.decode("utf-8")):
                        return SmartDeviceClient(host, int(match.group(3)))
        finally:
            sock.close()
