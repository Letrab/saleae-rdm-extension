# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting
from enum import Enum

CC_NAMES = {
    0x10: 'DISC_CMD',
    0x11: 'DISC_RSP',
    0x20: 'GET_CMD',
    0x21: 'GET_RSP',
    0x30: 'SET_CMD',
    0x31: 'SET_RSP',
}

PID_NAMES = {
    0x0001: 'DISC_UNIQUE',
    0x0002: 'DISC_MUTE',
    0x0003: 'DISC_UNMUTE',
    0x0010: 'PROXY_DEVS',
    0x0011: 'PROXY_DEV_CNT',
    0x0015: 'COMMS_STATUS',
    0x0020: 'QUEUED_MSG',
    0x0030: 'STATUS_MSGS',
    0x0031: 'STATUS_ID_DESC',
    0x0032: 'STATUS_ID_CLEAR',
    0x0033: 'SUBDEV_STATUS_THR',
    0x0034: 'QUEUED_MSG_SENSOR_SUB',
    0x0050: 'SUPPORTED_PIDS',
    0x0051: 'PID_DESC',
    0x0055: 'SUPPORTED_PIDS_ENH',
    0x0056: 'CTRL_FLAG_SUPPORT',
    0x0057: 'NACK_DESC',
    0x0058: 'PACKED_PID_SUB',
    0x0059: 'PACKED_PID_INDEX',
    0x0060: 'DEV_INFO',
    0x0070: 'PROD_DETAIL_IDS',
    0x0080: 'DEV_MODEL_DESC',
    0x0081: 'MFR_LABEL',
    0x0082: 'DEV_LABEL',
    0x0090: 'FACTORY_DEFAULTS',
    0x00A0: 'LANG_CAPS',
    0x00B0: 'LANGUAGE',
    0x00C0: 'SW_VER_LABEL',
    0x00C1: 'BOOT_SW_VER_ID',
    0x00C2: 'BOOT_SW_VER_LABEL',
    0x00E0: 'DMX_PERSONALITY',
    0x00E1: 'DMX_PERSONALITY_DESC',
    0x00F0: 'DMX_START_ADDR',
    0x0120: 'SLOT_INFO',
    0x0121: 'SLOT_DESC',
    0x0122: 'DEFAULT_SLOT_VAL',
    0x0200: 'SENSOR_DEF',
    0x0201: 'SENSOR_VAL',
    0x0202: 'SENSOR_RECORD',
    0x0400: 'DEV_HOURS',
    0x0401: 'LAMP_HOURS',
    0x0402: 'LAMP_STRIKES',
    0x0403: 'LAMP_STATE',
    0x0404: 'LAMP_ON_MODE',
    0x0405: 'DEV_POWER_CYC',
    0x0500: 'DISPLAY_INVERT',
    0x0501: 'DISPLAY_LEVEL',
    0x0600: 'PAN_INVERT',
    0x0601: 'TILT_INVERT',
    0x0602: 'PAN_TILT_SWAP',
    0x0603: 'RTC',
    0x1000: 'IDENTIFY',
    0x1001: 'RESET',
    0x1002: 'POWER_STATE',
    0x1003: 'SELFTEST',
    0x1004: 'SELFTEST_DESC',
    0x1005: 'CAPTURE_PRESET',
    0x1006: 'PRESET_PLAYBACK',
}

REQUEST_CC_SET = {0x10, 0x20, 0x30}
RESPONSE_CC_SET = {0x11, 0x21, 0x31}

class State(Enum):
    PARSE_START = (0, '', 0)
    PARSE_SUBSTART = (1, '_sub', 1)
    PARSE_LENGTH = (2, '_length', 1)
    PARSE_DST = (3,'_dst', 6)
    PARSE_SRC = (4, '_src', 6)
    PARSE_TN = (5, '_tn', 1)
    PARSE_PORTID = (6, '_portid', 1)
    PARSE_MSGCOUNT = (7, '_msgcount', 1)
    PARSE_SUBDEV = (8, '_subdevice', 2)
    PARSE_CC = (9, '_cc', 1)
    PARSE_PID = (10, '_pid', 2)
    PARSE_PDL = (11, '_pdl', 1)
    PARSE_PD = (12, '_pd', 0)
    PARSE_CHECKSUM = (13, '_checksum', 2)
    PARSE_END = (14, '', 0)

    @property
    def next(self):
        return STATE_NEXT[self]


STATE_ORDER = list(State)
STATE_NEXT = {state: STATE_ORDER[i + 1] for i, state in enumerate(STATE_ORDER[:-1])}
STATE_NEXT[State.PARSE_END] = State.PARSE_END


class RDMPacket():
    def __init__(self, debug=False):
        self._state = State.PARSE_START
        self._tempSize = 0
        self._debug = debug

        self._sub = bytearray()
        self._length = bytearray()
        self._dst = bytearray()
        self._src = bytearray()
        self._tn = bytearray()
        self._portid = bytearray()
        self._msgcount = bytearray()
        self._subdevice = bytearray()
        self._cc = bytearray()
        self._pid = bytearray()
        self._pdl = bytearray()
        self._pd = bytearray()
        self._checksum = bytearray()
        self._state_buffers = {
            State.PARSE_SUBSTART: self._sub,
            State.PARSE_LENGTH: self._length,
            State.PARSE_DST: self._dst,
            State.PARSE_SRC: self._src,
            State.PARSE_TN: self._tn,
            State.PARSE_PORTID: self._portid,
            State.PARSE_MSGCOUNT: self._msgcount,
            State.PARSE_SUBDEV: self._subdevice,
            State.PARSE_CC: self._cc,
            State.PARSE_PID: self._pid,
            State.PARSE_PDL: self._pdl,
            State.PARSE_PD: self._pd,
            State.PARSE_CHECKSUM: self._checksum,
        }
        # self._data = b''

    def printParam(self, state, doPrint=True):
        (idx, param, size) = state.value
        if doPrint:
            return {param.replace('_', ''): '0x'+getattr(self, param).hex()}
        else:
            return {}

    def _format_named_value(self, value_bytes, names, width, include_hex=False):
        if not value_bytes:
            return ''
        value = int.from_bytes(value_bytes, "big")
        name = names.get(value)
        if name:
            if include_hex:
                return f"{name} (0x{value:0{width}X})"
            return name
        return f"0x{value:0{width}X}"

    def _pid_name(self):
        if not self._pid:
            return None
        pid_value = int.from_bytes(self._pid, "big")
        return PID_NAMES.get(pid_value)

    def _pid_is_label(self):
        name = self._pid_name()
        return bool(name and (name.endswith('_LABEL') or name.endswith('DEV_MODEL_DESC')))

    def _format_pd_value(self, include_hex=False):
        pdl_value = int.from_bytes(self._pdl, "big") if self._pdl else 0
        if pdl_value == 0:
            return ''
        pd = self._pd[:pdl_value] if self._pd else b''
        if self._pid_is_label():
            pd = pd[:32].split(b'\x00', 1)[0]
            text = pd.decode('ascii', errors='replace')
            if include_hex:
                return f"{text}"
            return text
        return '0x' + pd.hex()

    def process_data(self, data):
        if self._state == State.PARSE_END:
            return True

        view = memoryview(data)
        offset = 0
        while offset < len(view):
            if self._state == State.PARSE_PD:
                size = int.from_bytes(self._pdl, "big") if self._pdl else 0
            else:
                size = self._state.value[2]

            if size == 0 or self._tempSize == size:
                self._state = self._state.next
                self._tempSize = 0
                if self._state == State.PARSE_END:
                    return True
                continue

            remaining = size - self._tempSize
            if remaining <= 0:
                self._state = self._state.next
                self._tempSize = 0
                if self._state == State.PARSE_END:
                    return True
                continue

            take = min(remaining, len(view) - offset)
            param = self._state.value[1]
            buf = self._state_buffers.get(self._state)
            if buf is not None:
                buf.extend(view[offset:offset + take])
            self._tempSize += take
            offset += take

            if self._tempSize == size:
                self._state = self._state.next
                self._tempSize = 0
                if self._state == State.PARSE_END:
                    return True

        return self._state == State.PARSE_END

    def get_analyzer_frame(self, start_time, end_time, break_time, frame_type='rdm'):
        entries = {}
        printVerbose = self._debug
        length_val = int.from_bytes(self._length, "big") if self._length else 0
        tn_val = int.from_bytes(self._tn, "big") if self._tn else 0
        portid_val = int.from_bytes(self._portid, "big") if self._portid else 0
        msgcount_val = int.from_bytes(self._msgcount, "big") if self._msgcount else 0
        subdevice_val = int.from_bytes(self._subdevice, "big") if self._subdevice else 0
        pid_val = int.from_bytes(self._pid, "big") if self._pid else 0
        pdl_val = int.from_bytes(self._pdl, "big") if self._pdl else 0

        # Stable insertion order for table columns.
        if printVerbose:
            if self._length:
                entries.update({'length': str(length_val)})
            else:
                entries.update({'length': ''})
        entries.update({'src': '0x' + self._src.hex()})
        entries.update({'dst': '0x' + self._dst.hex()})
        if printVerbose:
            if self._tn:
                entries.update({'tn': str(tn_val)})
            else:
                entries.update({'tn': ''})
            if self._portid:
                entries.update({'portid': str(portid_val)})
            else:
                entries.update({'portid': ''})
            if self._msgcount:
                entries.update({'msgcount': str(msgcount_val)})
            else:
                entries.update({'msgcount': ''})
            if break_time is not None:
                entries.update({'breaktime': str(round(break_time.__float__()*1000, 4)) + ' ms'})
            else:
                entries.update({'breaktime': ''})
        if self._subdevice:
            entries.update({'subdev': str(subdevice_val)})
        else:
            entries.update({'subdev': ''})
        entries.update({'cc': self._format_named_value(self._cc, CC_NAMES, 2, printVerbose)})
        entries.update({'pid': self._format_named_value(self._pid, PID_NAMES, 4, printVerbose)})
        if printVerbose:
            entries.update({'pid_hex': f"0x{pid_val:04X}" if self._pid else ''})
        if self._pdl:
            entries.update({'pdl': str(pdl_val)})
        else:
            entries.update({'pdl': ''})
        entries.update({'pd': self._format_pd_value(printVerbose)})
        entries.update(self.printParam(State.PARSE_CHECKSUM, printVerbose))


        return AnalyzerFrame(frame_type, start_time, end_time, entries)

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    debug_setting = ChoicesSetting(label='Debug', choices=('Off', 'On'))
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'rdm_cmd': {
            'format': '{{data.cc}} - {{data.pid}}'
        },
        'rdm_rsp': {
            'format': '{{data.cc}} - {{data.pid}}'
        },
        'rdm_unk': {
            'format': '{{data.cc}} - {{data.pid}}'
        },
    }

    def __init__(self):
        self._packet = None
        self._start_time = None
        self._frameStartTime = 0
        self._breakStartTime = 0
        self._last_byte = b''
        self._console = False
        self._last_frame_start = None
        self._last_frame_end = None
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

        # print("Settings:", self.my_string_setting,
        #       self.my_number_setting, self.my_choices_setting)

    def _packet_cc(self, packet):
        return int.from_bytes(packet._cc, "big") if len(packet._cc) == 1 else None

    def _format_console_line(self, tag, packet, start_time, end_time, break_time):
        src = '0x' + packet._src.hex() if packet._src else ''
        dst = '0x' + packet._dst.hex() if packet._dst else ''
        cc = packet._format_named_value(packet._cc, CC_NAMES, 2, True)
        pid = packet._format_named_value(packet._pid, PID_NAMES, 4, True)
        pdl = '0x' + packet._pdl.hex() if packet._pdl else ''
        pd = packet._format_pd_value(True)
        return (
            f"RDM {tag} "
            f"src={src} dst={dst} "
            f"cc={cc} pid={pid} pdl={pdl} pd={pd}"
        )

    def _print_complete(self, tag, packet, start_time, end_time, break_time):
        if not self._console:
            return
        line = self._format_console_line(tag, packet, start_time, end_time, break_time)
        print(line)

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

        # Debug controls console output only.
        self._console = (self.debug_setting == 'On')
        self._last_frame_start = frame.start_time
        self._last_frame_end = frame.end_time

        if 'error' in frame.data:
            # Possible break
            if frame.data['error'] == 'framing':
                self._start_time = frame.start_time
                self._breakStartTime = frame.start_time

        # Load byte
        data = frame.data['data']
        # print("length", len(frame.data['data']))

        # Process the data
        if not self._packet:
            # This is the start of a new packet - determine the type based on the first byte

            if data != b'\xCC':
                self._last_byte = data
                return None

            self._frameStartTime = frame.start_time
            if self._start_time == None: self._start_time = self._frameStartTime
            if self._breakStartTime != 0:
                self._breakTime =  self._frameStartTime - self._breakStartTime
            else:
                self._breakTime = 0
            self._packet = RDMPacket(self.debug_setting == 'On')

        elif self._packet.process_data(data):
            # This is the end of the packet signalled by the packet class
            packet = self._packet
            packet_start_time = self._start_time
            packet_end_time = frame.end_time
            packet_break_time = self._breakTime

            # reset variables
            self._packet = None
            self._start_time = None
            self._frameStartTime = 0
            self._breakStartTime = 0
            self._last_byte = data

            cc = self._packet_cc(packet)
            if cc in REQUEST_CC_SET:
                result = packet.get_analyzer_frame(
                    packet_start_time,
                    packet_end_time,
                    packet_break_time,
                    'rdm_cmd',
                )
                self._print_complete('CMD', packet, packet_start_time, packet_end_time, packet_break_time)
            elif cc in RESPONSE_CC_SET:
                result = packet.get_analyzer_frame(
                    packet_start_time,
                    packet_end_time,
                    packet_break_time,
                    'rdm_rsp',
                )
                self._print_complete('RSP', packet, packet_start_time, packet_end_time, packet_break_time)
            else:
                result = packet.get_analyzer_frame(
                    packet_start_time,
                    packet_end_time,
                    packet_break_time,
                    'rdm_unk',
                )
                self._print_complete('UNK', packet, packet_start_time, packet_end_time, packet_break_time)

            return result

        return None
