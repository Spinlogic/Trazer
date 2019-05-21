'''
Trace storage and tracing functionality.
'''

import json
import logging


class Trace(object):

    def __init__(self, tracefn):
        self.trace = {}
        with open(tracefn, "r") as tracefile:
            self.trace = json.load(tracefile)
        self.numpackets = len(self.trace)
        self.current_frame_index = -1      # current frame number inside a trace
        self.logger = logging.getLogger(__name__)


    def get_next_frame_index(self):
        self.current_frame_index += 1
        if(self.current_frame_index >= self.numpackets):
            return -1
        return self.current_frame_index


    def get_frame(self, index):
        assert(index < len(self.trace))
        return self.trace[index]["_source"]["layers"]

