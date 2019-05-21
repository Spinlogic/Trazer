'''
Test Case.

Traverses a trace applying the rules from a template sequentially.
'''

import json
import re
import logging
from .template import TestTemplate

class TestCase(object):

    def __init__(self, filename, trace):
        self.logger = logging.getLogger(__name__)
        self.trace = trace
        self.current_rule_index = 0
        self.current_frame_index = 0
        self.tcvars = {}
        with open(filename, "r") as tempfile:
            tc_description = json.load(tempfile)
            assert("template" in tc_description.keys())     # Raise exception if there is not template
            if("import" in tc_description):
                if(len(tc_description["import"]) > 0):
                    for import_file in tc_description["import"]:
                        self.logger.info("Import variables from file {}".format(import_file))
                        self._parse_imported_file(import_file)
            if("variables" in tc_description):
                variables = list(tc_description["variables"].keys())
                if(len(variables) > 0):
                    for variable in variables:
                        self.tcvars[variable] = tc_description["variables"][variable]
            self.template = TestTemplate(tc_description["template"])
        self.__result = False


    def _parse_imported_file(self, import_file):
        with open(import_file, "r") as var_file:
            for line in var_file:
                line = line.strip()
                name_val = line.split(" #", 1)
                name_val = name_val.split(num=1)
                name = name_val[0].strip()
                value = name_val[1].strip()
                self.tcvars[name] = value


    def get_result(self):
        return self.__result


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
        self.current_rule_index = self.template.get_next_rule_index()
        self.current_frame_index = self.trace.get_next_frame_index()
        while(self.current_rule_index >= 0):   # iterate rule by rule
            self.logger.info("current_rule: {}".format(self.current_rule_index))
            rule = self.template.get_rule(self.current_rule_index)
            self.apply_stored_variables(rule)
            while(self.current_frame_index >= 0):   # match remaining frames to the current rule
                self.logger.info("Processing frame: {}.".format(self.current_frame_index))
                frame = self.trace.get_frame(self.current_frame_index)
                isframesmatch = self.apply_rule(rule, frame)
                self.current_frame_index = self.trace.get_next_frame_index()  # increment here
                if(isframesmatch == True):
                    self.logger.debug("isframesmatch: {}. Rule matched!!!".format(isframesmatch))
                    break   # rule has been matched
            if(isframesmatch == False):
                self.logger.debug("No frames matched")
                break   # No packet matched the rule
            self.current_rule_index = self.template.get_next_rule_index()
            self.logger.debug("Next rule to match {}".format(self.current_rule_index))
        self.__result = isframesmatch


    def _is_match_dict(self, protocol, subrule, framedict):
        '''
        Iterator to math subrule dict trees inside a frame.
        Used to iterate dictionaries inside rules until we get to the actual rule. For example, in rule
        {
            "msg_hdr_tree": {
                "CSeq": "^1"
            },
            "optional": false
        },
        this iterator will iterate until it find the value of "CSeq".

        :param protocol: protocol prefix (e.g. ip, udp, sip, etc)
        :param subrule: dictionary with one field to match
        :param framedict: dictionary of frame to match against the subrule
        :return: -1 if not found.
                  0 if found but value does not match
                  1 if found and value matches
        '''
        matchtype = 1
        for key in subrule.keys():
            if(key == "optional"):
                continue
            if(matchtype != 1):
                break
            frkey = protocol + "." + key   # frame key
            self.logger.debug("Template Key: {}   Frame Key: {}".format(key, frkey))
            if frkey in framedict.keys():
                if(type(framedict[frkey]) is not dict):
                    self.logger.debug(
                        "Values: {}   {}".format(subrule[key], framedict[frkey]))
                    if(type(framedict[frkey]) is str):
                        searchres = re.search(subrule[key], framedict[frkey])
                        if(searchres == None):
                            matchtype = 0
                        elif(len(searchres.group()) == 0):
                            matchtype = 0
                        else:
                            matchtype = 1
                    else:
                        if(subrule[key] != framedict[frkey]):
                            matchtype = 0
                        else:
                            matchtype = 1
                else:
                    self.logger.debug("{} is dictionary. Iterating.".format(frkey))
                    matchtype = self._is_match_dict(protocol, subrule[key], framedict[frkey])
            else:
                matchtype = -1
            self.logger.debug("matchtype: {}".format(matchtype))
        return matchtype


    def apply_rule(self, rule, frame):
        '''
        Checks whether the frame matches the current rule. Iterates the rule and the frame to see if the frame contains
        the parameters defined in the rule and if the value of these parameters match.
        :param frame: dictionary with the content of a wireshark frame.
        :return: true if the packet matches the current rule
        '''
        self.logger.debug("current rule has subrules for protocols: {}".format(list(rule["match"].keys())))
        if(len(frame.keys()) == 0): # empty frame
            return False
        ismatch = True
        for protocol in rule["match"]:
            if(protocol not in frame):
                ismatch = False
            if(ismatch == False):
                self.logger.debug("No match. Breaking loop.")
                break
            self.logger.info("checking subrules for protocol {}".format(protocol))
            for subrule in rule["match"][protocol]:
                isoptional = False
                if("optional" in subrule):
                    isoptional = subrule["optional"]
                matchtype = self._is_match_dict(protocol, subrule, frame[protocol])
                if(isoptional == True):
                    if(matchtype == -1 or matchtype == 1):
                        msg = "Optional and not present. Match!!!" if(matchtype == -1) else \
                            "Optional, present and value matches."
                        self.logger.debug("{}".format(msg))
                        ismatch = True
                    else:
                        self.logger.debug("{}".format("Optional, present and value does not match."))
                        ismatch = False
                else:
                    if(matchtype == 1):
                        self.logger.debug("Mandatory, present and value matches.")
                        ismatch = True
                    else:
                        msg = "Mandatory and not present. No Match." if (matchtype == -1) else \
                            "Mandatory, present and value does not match."
                        self.logger.debug("{}".format(msg))
                        ismatch = False
                if(ismatch == False):
                    break
        if(ismatch == True):
            self.logger.info("Frame {} matches rule {}!!!".format(self.current_frame_index, self.current_rule_index))
            self.logger.debug("Now, search \"store\" section.")
            if "store" in rule.keys():
                self.parse_store_fields(rule["store"], frame)
        return ismatch


    def _iter_frame_for_store_fields(self, protocol, storedict, framedict):
        '''
        Iterates the keys in "storedict" inside framedict until it final value. For example, in the following:
        "msg_hdr_tree": {
                "callId": "Call-ID"
            }
        it iterates inside "msg_hdr_tree" until it finds "callId". Since "callId" is not a dict, it stops there.

        :param protocol: suffix for keys in temptdict inside framedict
        :param storedict: dictionary from inside "store" object of a rule. Must contains a single key.
        :param framedict: dictionary from a frame
        :return: Value of the field iterated if it exists. None otherwise.
        '''
        keys = list(storedict.keys())
        self.logger.debug("Keys: {}".format(keys))
        field = None
        value = None
        if (len(keys) > 0):
            frkey = protocol + "." + keys[0]
            self.logger.debug("Iteration for frkey: {}".format(frkey))
            if (frkey in framedict):  # check that the key exists in the frame
                if (type(framedict[frkey]) is dict):
                    self.logger.debug("frkey: {} is a dictionary".format(frkey))
                    field, value = self._iter_frame_for_store_fields(protocol, storedict[keys[0]], framedict[frkey])
                else:
                    field = storedict[keys[0]]
                    value = framedict[frkey]
                    self.logger.debug("variable {} set to value {}".format(field, value))
            else:
                self.logger.debug("No Key: {} in frame ".format(frkey))
        else:
            self.logger.debug("Empty dictionary")
        return field, value


    def parse_store_fields(self, store, frame):
        '''
        Parses the "store" area inside the rule and stores the required data into test case variables. If the data is
        not present, then the variables are defined with empty str value.
        This method shall only be called when "frame" has been positively matched against the subrules inside "match".

        For example, for the following "store" section of a rule
        "store": {
            "sip": [
                {
                    "msg_hdr_tree": {
                        "callId": "Call-ID"
                    }
                }
            ]
        }
        We will be looking for a field called sip.Call-ID inside path frame/sip/msg_hdr_tree
        If this field is found, then we will store is inside self.storedvars with key "callId".

        :param store:   "store" object inside a rule
        :param frame:   frame from which to extract the value
        :return: void
        '''
        # iterate all the protocols
        for protocol in store:
            self.logger.debug("Protocol \"{}\"".format(protocol))
            for item in store[protocol]:
                key, value = self._iter_frame_for_store_fields(protocol, item, frame[protocol])
                if (key is not None):
                    # store the value for future use
                    if (value is None):
                        self.tcvars[key] = ""
                    else:
                        self.tcvars[key] = value


    def _iter_rule_for_vars(self, tempdict):
        '''
        Iterates the keys in tempdict (template) searching for variables to replace.
        :param tempdict: dictionary to iterate (protocol item inside a TC template).
        :return:
        '''
        for key in tempdict.keys():
            if(type(tempdict[key]) is not dict):
                if(type(tempdict[key]) is str):
                    search_var = re.search("{{(.*)}}", tempdict[key])
                    if(search_var):
                        var_name = search_var.group(1)
                        self.logger.debug("Found variable to replace {}".format(var_name))
                        assert (var_name in self.tcvars), "{} not stored.".format(var_name)
                        tempdict[key] = re.sub("{{(.*)}}", self.tcvars[var_name], tempdict[key])
                        self.logger.debug("{} set to value {}".format(key, tempdict[key]))
            else:
                self.logger.debug("{}".format("{} is a dictionary. New iteration.".format(key)))
                self._iter_rule_for_vars(tempdict[key])


    def apply_stored_variables(self, rule):
        '''
        Searches the rule for variables (inside double brackets {{}}) and replaces them with the stored
        value, if it exists. If it does not exist, then raises an exception.
        :param rule: index of the rules to which variables shall be set.
        :return: void . Raises exception if variable does no exist.
        '''
        assert ("match" in rule), "Invalid rule. Nothing to match."
        self.logger.debug("Rule to iterate to apply stored variables\n{}".format(rule))
        for protocol in rule["match"]:
            self.logger.debug("Iterating protocol {} for variable replacement".format(protocol))
            subrule_index = 0
            for subrule in rule["match"][protocol]:
                self.logger.debug("Iterating subrule {} for variable replacement".format(subrule_index))
                self._iter_rule_for_vars(subrule)
                subrule_index += 1

