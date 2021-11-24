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
WirelessCallback = Callable[
    ["SmartDeviceClient", SmartDeviceOpcode, CalibrePayload], Optional[ResponsePayload]
]

CLIENT_NAME = "smart-device-client"
DEVICE = "Kobo"
DEVICE_NAME = f"{CLIENT_NAME} ({DEVICE})"
VERSION = "0.1.0"
VALID_EXTENSIONS = ["epub"]

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
        self.implementation = {
            SmartDeviceOpcode.NOOP: self.on_noop,
            SmartDeviceOpcode.OK: self.on_ok,
            SmartDeviceOpcode.BOOK_DONE: self.on_book_done,
            SmartDeviceOpcode.CALIBRE_BUSY: self.on_calibre_busy,
            SmartDeviceOpcode.SET_LIBRARY_INFO: self.on_set_library_info,
            SmartDeviceOpcode.DELETE_BOOK: self.on_delete_book,
            SmartDeviceOpcode.DISPLAY_MESSAGE: self.on_display_message,
            SmartDeviceOpcode.ERROR: self.on_error,
            SmartDeviceOpcode.FREE_SPACE: self.on_free_space,
            SmartDeviceOpcode.GET_BOOK_FILE_SEGMENT: self.on_get_book_file_segment,
            SmartDeviceOpcode.GET_BOOK_METADATA: self.on_get_book_metadata,
            SmartDeviceOpcode.GET_BOOK_COUNT: self.on_get_book_count,
            SmartDeviceOpcode.GET_DEVICE_INFORMATION: self.on_get_device_information,
            SmartDeviceOpcode.GET_INITIALIZATION_INFO: self.on_get_initialization_info,
            SmartDeviceOpcode.SEND_BOOKLISTS: self.on_send_booklists,
            SmartDeviceOpcode.SEND_BOOK: self.on_send_book,
            SmartDeviceOpcode.SEND_BOOK_METADATA: self.on_send_book_metadata,
            SmartDeviceOpcode.SET_CALIBRE_DEVICE_INFO: self.on_set_calibre_device_info,
            SmartDeviceOpcode.SET_CALIBRE_DEVICE_NAME: self.on_set_calibre_device_name,
            SmartDeviceOpcode.TOTAL_SPACE: self.on_total_space,
        }

    def on_unimplemented(
        self, opcode: SmartDeviceOpcode, payload: CalibrePayload
    ) -> None:
        logger.warning("received %s, which is is unimplemented. %s", opcode, payload)

    def on_noop(self, payload: CalibrePayload) -> Optional[ResponsePayload]:  # type: ignore
        logger.debug("NOOP: %s", payload)
        # This method shows a problem with the client structure, how does this method communicate intention to the serve method?
        # such as needing to disconnect
        # We can probably open a second command socket and send commands to it or something but that's janky
        # might be our best bet though
        # This is what I get for trying to make things nice for consumers and hiding the complexity

        # calibre wants to close the socket, time to disconnect
        if payload.get("ejecting"):
            # self.disconnected_by_server = true
            # self:disconnect()
            return (SmartDeviceOpcode.OK, {})
        # calibre announces the count of books that need more metadata
        elif payload.get("count"):
            return
        # calibre requests more metadata for a book by its index
        elif payload.get("priKey"):
            # TODO
            # local book = CalibreMetadata:getBookMetadata(arg.priKey)
            # logger.dbg(string.format("sending book metadata %d/%d", self.current, self.pending))
            # self:sendJsonData('OK', book)
            # if self.current == self.pending then
            #     self.current = nil
            #     self.pending = nil
            #     return
            # end
            # self.current = self.current + 1
            # return
            return (SmartDeviceOpcode.OK, {})
        # keep-alive NOOP
        return (SmartDeviceOpcode.OK, {})

    def on_ok(self, payload: CalibrePayload) -> Optional[ResponsePayload]:
        logger.debug("OK: %s", payload)

    def on_book_done(self, payload: CalibrePayload) -> Optional[ResponsePayload]:
        logger.debug("BOOK_DONE: %s", payload)

    def on_calibre_busy(self, payload: CalibrePayload) -> Optional[ResponsePayload]:
        logger.debug("CALIBRE_BUSY: %s", payload)

    def on_set_library_info(self, payload: CalibrePayload) -> Optional[ResponsePayload]:
        logger.warning("SET_LIBRARY_INFO received but not implemented: %s", payload)
        return (SmartDeviceOpcode.OK, {})

    def on_delete_book(self, payload: CalibrePayload) -> Optional[ResponsePayload]:
        logger.debug("DELETE_BOOK: %s", payload)

    def on_display_message(self, payload: CalibrePayload) -> Optional[ResponsePayload]:
        logger.debug("DISPLAY_MESSAGE: %s", payload)

    def on_error(self, payload: CalibrePayload) -> Optional[ResponsePayload]:
        logger.debug("ERROR: %s", payload)

    # FIXME: There is a bug somewhere in this client, presenting itself in on_free_space
    #        although I am not convinced it's actually a bug _with_ on_free_space. 
    # 
    #        The first time calibre sends us a FREE_SPACE message, everything goes great,
    #        but it makes multiple requests, 2 on connection and one every time you
    #        "update cached metadata on device". All of those subsequent calls fail.
    #
    #        ERROR: Error: Error communicating with device
    #
    #        'free_space_on_device'
    #
    #        Traceback (most recent call last):
    #          File "calibre/gui2/device.py", line 89, in run
    #          File "calibre/gui2/device.py", line 546, in _sync_booklists
    #          File "calibre/devices/smart_device_app/driver.py", line 50, in _synchronizer
    #          File "calibre/devices/smart_device_app/driver.py", line 1283, in free_space
    #        KeyError: 'free_space_on_device'
    #
    #        I don't see how we could not be sending an object that has the free_space_on_device key
    #        since there is no logic in this method, we just return a dict with that key, and the debug
    #        logs indicate that that's what we're sending
    #
    #        DEBUG:smart_device_client.smart_device_client:[5, {}]
    #        WARNING:smart_device_client.smart_device_client:FREE_SPACE received but not implemented: {}
    #        DEBUG:smart_device_client.smart_device_client:sending: "[b'\x00k\x8bEg', b'41[0, {"free_space_on_device": 1073741824}]']"
    #
    def on_free_space(self, payload: CalibrePayload) -> ResponsePayload:
        logger.warning("FREE_SPACE received but not implemented: %s", payload)
        return (SmartDeviceOpcode.OK, {"free_space_on_device": 1024 * 1024 * 1024})

    def on_get_book_file_segment(
        self, payload: CalibrePayload
    ) -> Optional[ResponsePayload]:
        logger.debug("GET_BOOK_FILE_SEGMENT: %s", payload)

    def on_get_book_metadata(
        self, payload: CalibrePayload
    ) -> Optional[ResponsePayload]:
        logger.debug("GET_BOOK_METADATA: %s", payload)

    def on_get_book_count(self, payload: CalibrePayload) -> ResponsePayload:
        logger.warning("GET_BOOK_COUNT received but not implemented: %s", payload)
        return (
            SmartDeviceOpcode.OK,
            {
                "willStream": True,
                "willScan": True,
                "count": 0,
            },
        )

    def on_get_device_information(self, payload: CalibrePayload) -> ResponsePayload:
        logger.warning("GET_DEVICE received but not implemented: %s", payload)
        return (
            SmartDeviceOpcode.OK,
            {
                "device_info": {
                    # 'device_store_uuid' = CalibreMetadata.drive.device_store_uuid,
                    "device_name": DEVICE_NAME,
                },
                "version": VERSION,
                "device_version": VERSION,
            },
        )

    def on_get_initialization_info(self, payload: CalibrePayload) -> ResponsePayload:
        logger.debug("default GET_INITIALIZATION_INFO handler called: %s", payload)

        # TODO: I'm not using this for anything at the moment, but I could
        # calibre_version = ".".join(map(str, payload["calibre_version"]))

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
            "appName": CLIENT_NAME,  # TODO: Configurable
            "acceptedExtensions": VALID_EXTENSIONS,  # TODO: Configurable
            "cacheUsesLpaths": True,
            "canAcceptLibraryInfo": True,
            "canDeleteMultipleBooks": True,
            "canReceiveBookBinary": True,
            "canSendOkToSendbook": True,
            "canStreamBooks": True,
            "canStreamMetadata": True,
            "canUseCachedMetadata": True,
            "ccVersionNumber": VERSION,
            "coverHeight": 240,
            "deviceKind": DEVICE,  # TODO: Configurable
            "deviceName": DEVICE_NAME,  # TODO Configurable
            "extensionPathLengths": [MAGIC_PATH_LENGTH for _ in VALID_EXTENSIONS],
            "passwordHash": "",  # TODO: getPasswordHash()
            "maxBookContentPacketLen": 4096,
            "useUuidFileNames": False,
            "versionOK": True,
        }
        return (SmartDeviceOpcode.OK, init_info)

    def on_send_booklists(self, payload: CalibrePayload) -> Optional[ResponsePayload]:
        logger.debug("SEND_BOOKLISTS: %s", payload)

    def on_send_book(self, payload: CalibrePayload) -> Optional[ResponsePayload]:
        logger.debug("SEND_BOOK: %s", payload)

    def on_send_book_metadata(
        self, payload: CalibrePayload
    ) -> Optional[ResponsePayload]:
        logger.debug("SEND_BOOK_METADATA: %s", payload)

    def on_set_calibre_device_info(self, payload: CalibrePayload) -> ResponsePayload:
        logger.warning("SET_CALIBRE_DEVICE_INFO received but not implemented: %s", payload)
        return (SmartDeviceOpcode.OK, {})

    # Can we even recieve this opcode? Or is it just for sending
    def on_set_calibre_device_name(
        self, payload: CalibrePayload
    ) -> Optional[ResponsePayload]:
        logger.debug("SET_CALIBRE_DEVICE_NAME: %s", payload)

    def on_total_space(self, payload: CalibrePayload) -> Optional[ResponsePayload]:
        logger.debug("TOTAL_SPACE: %s", payload)

    def serve(self):
        context = zmq.Context()
        socket = context.socket(zmq.STREAM)
        socket.connect("tcp://%s:%d" % (self.calibre_host[0], self.replied_port))

        try:
            id = socket.getsockopt(zmq.IDENTITY)
            logger.debug("id: \"%s\"", id)
            poller = zmq.Poller()
            poller.register(socket, zmq.POLLIN)

            while True:
                socks = dict(poller.poll())

                if socks.get(socket) == zmq.POLLIN:
                    buffer = []
                    cl = 0
                    # We always recieve this weird id value first that we don't care about
                    # Similar to the message in _send, guided by koreader, doesn't work without it.
                    _ = socket.recv()
                    message = socket.recv().decode("utf-8")
                    # regex is probably overkill for this parsing now that I've realized I can't just consume the whole message in one big recv
                    if match := CALIBRE_MESSAGE.match(message):
                        length = int(match.group("length"))
                        message = match.group("message")
                        buffer.append(message)
                        cl += len(message)

                        # If the payload is too big, we have to do those 2 recv calls in a loop until we've read in everything that was sent
                        while cl < length:
                            _ = socket.recv()
                            message = socket.recv().decode("utf-8")
                            buffer.append(message)
                            cl += len(message)
                        full_message = "".join(buffer)
                        logger.debug("recieved \"%s\"", full_message)

                        op, payload = json.loads(full_message)

                        opcode = SmartDeviceOpcode(op)
                        implementation = self.implementation.get(opcode) or (
                            lambda payload: self.on_unimplemented(opcode, payload)
                        )

                        ret = implementation(payload)
                        if ret:
                            self._send(socket, id, ret)
        # TODO: Narrow down the exception list?
        except Exception as e:
            logger.exception(e)
            raise
        finally:
            socket.close()
            context.term()

    def _send(self, socket: zmq.Socket, id: bytes, response: ResponsePayload) -> None:
        opcode, payload = response
        message = json.dumps([opcode.value, payload])
        # calibre exchanges these messages in this format:
        # LENGTH[OPCODE, MESSAGE]
        # Where LENGTH is for the array holding the opcode and message
        encoded = (str(len(message)) + message).encode()
        multipart = [id, encoded]
        logger.debug('sending: "%s"', multipart)
        # I have honestly no idea why I have to send_multipart with that id value
        # I'm just following the implementation in koreader, and it didn't work without it ¯\_(ツ)_/¯
        socket.send_multipart(multipart)

    @staticmethod
    def zeroconf_client() -> Optional["SmartDeviceClient"]:  # type: ignore
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(5)

        # This magic list of ports is from the calibre source
        # It's literally just some random ports they chose with the hope that
        # nothing else happens to listen on them
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
