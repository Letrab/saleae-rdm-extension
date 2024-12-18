# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from enum import Enum

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
        return list(State)[self.value[0] + 1]


class RDMPacket():
    def __init__(self, debug=False):
        self._state = State.PARSE_START
        self._tempSize = 0
        self._debug = debug

        self._sub =  b''
        self._length =  b''
        self._dst =  b''
        self._src =  b''
        self._tn =  b''
        self._portid =  b''
        self._msgcount =  b''
        self._subdevice =  b''
        self._cc =  b''
        self._pid =  b''
        self._pdl =  b''
        self._pd =  b''
        self._checksum =  b''

        # self._data = b''

    def printParam(self, state, doPrint=True):
        (idx, param, size) = state.value
        if doPrint:
            return {param.replace('_', ''): '0x'+getattr(self, param).hex()}
        else:
            return {}

    def printDeb(self, *args, **kwargs):
        if self._debug: print(*args, **kwargs)

    def process_data(self, data):
        (idx, param, size) = self._state.value
        if self._state == State.PARSE_END:
            return True

        while data:

            if self._state == State.PARSE_PD:
                size = int.from_bytes(self._pdl, "big")
                self.printDeb("PDL:", self._pdl, size)

            self.printDeb("parsing", param, self._tempSize, size)

            if (size == 0 or self._tempSize == size):
                self.printDeb("going to next at BEGIN")
                self._state = self._state.next
                self._tempSize = 0
                (idx, param, size) = self._state.value


            if hasattr(self, param):
                newData = getattr(self, param)
                newData += data
                setattr(self, param, newData)
                self._tempSize = self._tempSize+1
            else:
                print("Got no param", param)

            # print(self._state.next)
            # if self._new:
            #     if data != b'\x01':
            #         return false

            #     self._new = False
            #     self._isRDM = True
            #     return False

            # # Load the data bytes
            # self._data += data

            # assert self._length is not None
            # # Only return true if we have the full packet
            # return len(self._data) >= self._length

            if (size == 0 or self._tempSize == size):
                if hasattr(self, param): self.printDeb("DONE param", param, getattr(self, param).hex())
                self.printDeb("going to next at END")
                self._state = self._state.next
                self._tempSize = 0

            if self._state == State.PARSE_END:
                return True
            else:
                return False

    def get_analyzer_frame(self, start_time, end_time, break_time, verbose_setting):
        entries = {}
        printVerbose = verbose_setting == 'On'
        # Serial Analyzer only reports a short framing error, so start counting from beginning of the break to begin of next frame
        # 26.2us is the measured average duration for the MaB and start bits of the first CC frame
        breakTimeRound = round(break_time.__float__()*1000000-26.2)
        displayBreak = breakTimeRound if break_time != 0 else "ERROR!"

        entries.update({'breakTime': displayBreak})
        entries.update(self.printParam(State.PARSE_SUBSTART, printVerbose))
        entries.update(self.printParam(State.PARSE_LENGTH, printVerbose))
        entries.update(self.printParam(State.PARSE_DST))
        entries.update(self.printParam(State.PARSE_SRC))
        entries.update(self.printParam(State.PARSE_TN, printVerbose))
        entries.update(self.printParam(State.PARSE_PORTID, printVerbose))
        entries.update(self.printParam(State.PARSE_MSGCOUNT, printVerbose))
        entries.update(self.printParam(State.PARSE_SUBDEV, printVerbose))
        entries.update(self.printParam(State.PARSE_CC))
        entries.update(self.printParam(State.PARSE_PID))
        entries.update(self.printParam(State.PARSE_PDL))
        entries.update(self.printParam(State.PARSE_PD))
        entries.update(self.printParam(State.PARSE_CHECKSUM, printVerbose))


        return AnalyzerFrame('rdm', start_time, end_time, entries)

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    debug_setting = ChoicesSetting(label='Debug', choices=('Off', 'On'))
    verbose_setting = ChoicesSetting(label='Verbose', choices=('Off', 'On'))
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    # result_types = {
    #     'mytype': {
    #         'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
    #     }
    # }

    def __init__(self):
        self._packet = None
        self._start_time = None
        self._frameStartTime = 0
        self._breakStartTime = 0
        self._last_byte = b''
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''

        # print("Settings:", self.my_string_setting,
        #       self.my_number_setting, self.my_choices_setting)

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''

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
                return #AnalyzerFrame('unknown', frame.start_time, frame.end_time, {})

            self._frameStartTime = frame.start_time
            if self._start_time == None: self._start_time = self._frameStartTime
            if self._breakStartTime != 0:
                self._breakTime =  self._frameStartTime - self._breakStartTime
            else:
                self._breakTime = 0
            self._packet = RDMPacket(self.debug_setting == 'On')

        elif self._packet.process_data(data):
            # This is the end of the packet signalled by the packet class
            result = self._packet.get_analyzer_frame(self._start_time, frame.end_time, self._breakTime, self.verbose_setting)

            # reset variables
            self._packet = None
            self._start_time = None
            self._frameStartTime = 0
            self._breakStartTime = 0
            self._last_byte = data

            # post the result
            return result

        # If ch is 'H' or 'l', output a frame
        # if ch == b'\xcc':
        #     return AnalyzerFrame('mytype', frame.start_time, frame.end_time, {
        #         'input_type': frame.type
        #     })

        # Return the data frame itself
        # return AnalyzerFrame('mytype', frame.start_time, frame.end_time, {
        #     'input_type': frame.type
        # })
