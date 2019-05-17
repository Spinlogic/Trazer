'''
Implements TC template functionality
'''

import json
import re
import logging


class TestTemplate(object):

    def __init__(self, filename):
        self.template = {}
        with open(filename, "r") as tempfile:
            self.template = json.load(tempfile)
        self.current_rule_index = -1
        self.logger = logging.getLogger(__name__)
        self.storedvars = {}


    def _iter_frame_for_store_fields(self, protocol, tempdict, framedict):
        '''
        Iterates the keys in tempdict inside framedict.
        :param protocol: suffix for keys in temptdict inside framedict
        :param tempdict: dictionary from a template. Must contains a single key.
        :param framedict: dictionary from a frame
        :return: Value of the field iterated if it exists. None otherwise.
        '''
        keys = list(tempdict.keys())
        self.logger.debug("Keys: {}".format(keys))
        field = None
        value = None
        if (len(keys) > 0):
            frkey = protocol + "." + keys[0]
            self.logger.debug("Iteration for frkey: {}".format(frkey))
            if (frkey in framedict):   # check that the key exists in the frame
                if(type(framedict[frkey]) is dict):
                    self.logger.debug("frkey: {} is a dictionary".format(frkey))
                    field, value = self._iter_frame_for_store_fields(protocol, tempdict[keys[0]], framedict[frkey])
                else:
                    field = tempdict[keys[0]]
                    value = framedict[frkey]
                    self.logger.debug("variable {} set to value {}".format(field, value))
            else:
                self.logger.debug("No Key: {} in frame ".format(frkey))
        else:
            self.logger.debug("Empty dictionary")
        return field, value


    def _parse_store_fields(self, rule_index, frame):
        '''
        Parses the "store" area inside the rule with index "rule_index" and stores the required data
        into variables. If the data is not present, then the variables are defined with empty str value.
        This method shall only be called when frame is matched against the rules inside "match".

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

        :param rule_index:  index of the rule to parse
        :param frame:   frame from which to extract the value
        :return: void
        '''
        if "store" in self.template[rule_index].keys():
            #iterate the protocols
            for protocol in self.template[rule_index]["store"]:
                self.logger.debug("Protocol \"{}\"".format(protocol))
                for item in self.template[rule_index]["store"][protocol]:
                    key, value = self._iter_frame_for_store_fields(protocol, item, frame[protocol])
                    if(key is not None):
                        # store the value for future use
                        if(value is None):
                            self.storedvars[key] = ""
                        else:
                            self.storedvars[key] = value
        else:
            self.logger.debug("No \"store\" field.")


    def _is_match_dict(self, protocol, subrule, framedict):
        '''
        Iterator to math dictionary trees inside a frame
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


    def get_next_rule_index(self):
        self.current_rule_index += 1
        if(self.current_rule_index >= len(self.template)):
            return -1
        return self.current_rule_index


    def apply_current_rule(self, frame):
        '''
        Checks if the frame matches the current rule.
        :param frame: dictionary with the content of a wireshark frame.
        :return: true if the packet matches the current rule
        '''
        self.logger.info("Rule index: {}".format(self.current_rule_index))
        self.logger.debug("current rule has subrules for protocols: {}".format(
            list(self.template[self.current_rule_index]["match"].keys())))
        if(len(frame.keys()) == 0): # empty frame
            return False
        ismatch = True
        for protocol in self.template[self.current_rule_index]["match"]:
            if(protocol not in frame):
                ismatch = False
            if(ismatch == False):
                self.logger.debug("No match. Breaking loop.")
                break
            self.logger.info("checking protocol {}".format(protocol))
            for subrule in self.template[self.current_rule_index]["match"][protocol]:
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
            self.logger.debug("Now, search \"store\" section.")
            self._parse_store_fields(self.current_rule_index, frame)
        return ismatch


    def _iter_rule_for_vars(self, tempdict):
        '''
        Iterates the keys in tempdict searching for variables to replace.
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
                        assert (var_name in self.storedvars), "{} not stored.".format(var_name)
                        tempdict[key] = self.storedvars[var_name]
                        self.logger.debug("{} set to value {}".format(key, tempdict[key]))
            else:
                self.logger.debug("{}".format("{} is a dictionary. New iteration.".format(key)))
                self._iter_rule_for_vars(tempdict[key])


    def apply_stored_variables(self, ruleindex):
        '''
        Searches the rule for variables (inside double brackets {{}}) and replaces them with the stored
        value, if it exists. If it does not exist, then raises an exception.
        :param rule: index of the rules to which variables shall be set.
        :return: void . Raises exception if variable does no exist.
        '''
        rule = self.template[ruleindex]
        assert ("match" in rule), "Invalid rule. Nothing to match."
        for protocol in rule["match"]:
            subrule_index = 0
            for subrule in rule["match"][protocol]:
                self.logger.debug(
                    "Iterate protocol {} in rule {} and subrule {} for variable replacement".format(
                        protocol, ruleindex, subrule_index))
                self._iter_rule_for_vars(subrule)
                subrule_index += 1
