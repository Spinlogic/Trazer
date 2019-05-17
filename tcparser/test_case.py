'''
Test Case.

Traverses a trace applying the rules from a template sequentially.
'''

import logging

class TestCase(object):

    def __init__(self, trace, template):
        self.trace = trace
        self.template = template
        self.result = False
        self.logger = logging.getLogger(__name__)

    def run(self):
        '''
        Runs a test case.
        TC rules must be specified in the other they must be matched.
        When a match is found for a rule, the following rule matched on the
        remaining frames.
        TODO: Allow some rules to be matched in no "strict" order of frames.
        :return:
        '''
        isframesmatch = False
        current_rule = self.template.get_next_rule_index()
        current_frame = self.trace.get_next_frame_index()
        while(current_rule >= 0):   # iterate rule by rule
            self.logger.info("current_rule: {}".format(current_rule))
            self.logger.info("current_frame: {}".format(current_frame))
            self.template.apply_stored_variables(current_rule)
            while(current_frame >= 0):   # match remaining frames to the current rule
                isframesmatch = self.template.apply_current_rule(self.trace.get_current_frame())
                current_frame = self.trace.get_next_frame_index()
                self.logger.debug("Next frame to match {}".format(current_frame))
                if(isframesmatch == True):
                    self.logger.debug("isframesmatch: {}".format(isframesmatch))
                    break   # rule has been matched
            if(isframesmatch == False):
                self.logger.debug("No frames matched")
                break   # No packet matched the rule
            current_rule = self.template.get_next_rule_index()
            self.logger.debug("Next rule to match {}".format(current_rule))
        self.result = isframesmatch


    def get_result(self):
        return self.result