'''
Test Case.

Traverses a trace applying the rules from a template sequentially.
'''

import json
import re
import logging
from .template import TestTemplate
from .tc_report import TcReport

class TestCase(object):

    def __init__(self, filename, trace):
        self.logger = logging.getLogger(__name__)
        self.__trace = trace
        self.__current_rule_index = 0
        self.__current_frame_index = 0
        self.__tcvars = {}
        self.__report = TcReport()
        with open(filename, "r") as tcfp:
            tc_description = json.load(tcfp)
            assert("template" in tc_description)     # Raise exception if there is not template
            name = filename.split(".")  # default TC name = filename - extension
            self.filename = filename
            if("metadata" in tc_description):
                self.__report.set_field("metadata", tc_description["metadata"])
            if("import" in tc_description):
                if(len(tc_description["import"]) > 0):
                    for import_file in tc_description["import"]:
                        self.logger.info("Import variables from file {}".format(import_file))
                        self.__parse_imported_file(import_file)
            if("variables" in tc_description):
                variables = list(tc_description["variables"].keys())
                if(len(variables) > 0):
                    for variable in variables:
                        self.__tcvars[variable] = tc_description["variables"][variable]
                        self.logger.debug("variable {} set to {}".format(variable,
                                                                         tc_description["variables"][variable]))
            self.template = TestTemplate(tc_description["template"])
        self.__result = False

    def __parse_imported_file(self, import_file):
        '''
        Each line in an imported file contains either a comment or a tag / value.
        Tags cannot contain spaces (or tabs or new lines).
        Values can contain spaces and tabs , but not new lines. The can also not contains char # preceded by one or more
        spaces.
        Anything after # is a comment. Comments can be placed anywhere.
        :param import_file:
        :return:
        '''
        with open(import_file, "r") as var_file:
            for line in var_file:
                line = line.strip()
                if len(line) < 3:   # ignore empty lines and lines that cannot have a valid tag value content.
                    continue
                if line[0] == "#":  # whole line is a comment
                    continue
                name_val = line.split(" #", 1)[0]  # remove comment
                name_val = name_val.split(maxsplit=1)
                name = name_val[0].strip()
                value = name_val[1].strip()
                self.__tcvars[name] = value
                self.logger.debug("variable {} set to {}".format(name, value))

    def report(self, filepath):
        self.__report.set_result(self.__result)
        self.__report.save_report_to_file(filepath)

    def get_result(self):
        return self.__result

    def run(self):
        '''
        Runs a test case.
        Iterates a "template" inside a TC that contains rules to match.
        TC rules must be specified in the other that they must be matched.
        When a match is found for a rule, the following rule matched on the
        remaining frames.
        :return:
        '''
        isframesmatch = False
        self.__current_rule_index = self.template.get_next_rule_index()
        self.__current_frame_index = self.__trace.get_next_frame_index()
        while(self.__current_rule_index >= 0):   # iterate rule by rule
            self.logger.info("current_rule: {}".format(self.__current_rule_index))
            start_index = self.__current_frame_index  # store this to reset if it is an unmet optional rule
            self.logger.info("Storing current frame index: {}".format(start_index))
            rule = self.template.get_rule(self.__current_rule_index)
            self.__apply_stored_variables(rule)
            if "metadata" in rule:
                self.__report.new_rule(rule["metadata"])
            else:
                self.__report.new_rule()  # build report for new rule inside the TC template
            if "optional" in rule:
                isruleoptional = rule["optional"]
            else:
                isruleoptional = False
            while(self.__current_frame_index >= 0):   # match remaining frames to the current rule
                self.logger.info("Processing frame: {}.".format(self.__current_frame_index))
                frame = self.__trace.get_frame(self.__current_frame_index)
                isframesmatch = self.__apply_rule(rule, frame)
                self.__current_frame_index = self.__trace.get_next_frame_index()  # increment here
                if isframesmatch:
                    self.__report.add_to_current_rule("frame_number", self.__current_frame_index - 1)
                    isruleoptional = False  # Once a rule is matched, it stops being optional
                    self.logger.debug("isframesmatch: {}. Rule matched!!!".format(isframesmatch))
                    break   # rule has been matched
            # Frame matching is independent of rule verification. Once the rule has be matched we can check for
            # verification conditions.
            if isframesmatch:
                is_rule_verified = self.__verify_rule(rule)
                if not is_rule_verified:
                    self.logger.debug("Rule verification failed.")
                    isframesmatch = False
            self.__report.set_result_of_current_rule(isframesmatch, isruleoptional)
            if not isframesmatch:
                if not isruleoptional:
                    self.logger.debug("No frames matched. TC ends here.")
                    break   # No packet matched the rule
                else:
                    self.logger.info("Restoring current frame index to: {}".format(start_index))
                    self.__trace.set_frame_index(start_index)  # reset index
                    self.__current_frame_index = start_index
                    self.logger.debug("No frames matched but rule is optional.")
            self.__current_rule_index = self.template.get_next_rule_index()
            self.logger.debug("Next rule to match {}".format(self.__current_rule_index))
        if isframesmatch:
            self.__result = isframesmatch
        elif isruleoptional:
            self.__result = True

    def __verify_rule(self, rule):
        '''
        Checks that all the conditions in the list "verify" of the rule are met.
        :param rule: rule to verify
        :return:
        '''
        returnvalue = False
        if "verify" in rule:
            for ver_item in rule["verify"]:
                if "contains" in ver_item:
                    if ver_item["field"] in self.__tcvars:
                        if type(self.__tcvars[ver_item["field"]]) is list:
                            for listitem in self.__tcvars[ver_item["field"]]:
                                search_var = re.search("(.*)" + ver_item["contains"] + "(.*)", listitem)
                                if search_var:
                                    returnvalue = True
                                    break
                        else:
                            search_var = re.search("(.*)" + ver_item["contains"] + "(.*)",
                                                   self.__tcvars[ver_item["field"]])
                            if search_var:
                                returnvalue = True
                    else:
                        self.logger.debug("Field {} to verify is not inside __tcvars".format(ver_item["field"]))
                elif "is" in ver_item:
                    if ver_item["is"] == self.__tcvars[ver_item["field"]]:
                        returnvalue = True
                else:
                    self.logger.debug("Verify field contains no valid condition")
        else:
            returnvalue = True    # Nothing to verify
        return returnvalue

    def __is_match_dict(self, subrule, framedict):
        '''
        Iterator to match subrule dict trees inside a frame.
        Used to iterate dictionaries inside rules until we get to the actual rule. For example, in rule
        {
            "msg_hdr_tree": {
                "CSeq": "^1"
            },
            "optional": false
        },
        this iterator will iterate until it find the value of "CSeq".

        :param subrule: dictionary with one field to match
        :param framedict: dictionary of frame to match against the subrule
        :return: -1 not found.
                  0 found but value does not match
                  1 found and value matches
        '''
        matchtype = 1
        for key in subrule.keys():
            if(key == "optional"):
                continue
            if(matchtype != 1):
                break
            frkey = key   # frame key
            self.logger.debug("Template Key: {}   Frame Key: {}".format(key, frkey))
            if frkey in framedict.keys():
                self.logger.debug("frkey is a {}".format(type(framedict[frkey])))
                if(type(framedict[frkey]) is not dict):
                    self.logger.debug("Values: {}   {}".format(subrule[key], framedict[frkey]))
                    if(type(framedict[frkey]) is str):
                        searchres = re.search(subrule[key], framedict[frkey])
                        if(searchres == None):
                            matchtype = 0
                        elif(len(searchres.group()) == 0):
                            matchtype = 0
                        else:
                            matchtype = 1
                    elif(type(framedict[frkey]) is list):
                        for item in framedict[frkey]:
                            if(type(item) is str):
                                searchres = re.search(subrule[key], item)
                                if (searchres == None):
                                    matchtype = 0
                                elif (len(searchres.group()) == 0):
                                    matchtype = 0
                                else:
                                    matchtype = 1
                                    break
                            elif(type(item) is dict):
                                matchtype = self.__is_match_dict(subrule[key], item)
                                if(matchtype == 1):
                                    break
                            else:
                                if (subrule[key] != item):
                                    matchtype = 0
                                else:
                                    matchtype = 1
                                    break
                    else:
                        if(subrule[key] != framedict[frkey]):
                            matchtype = 0
                        else:
                            matchtype = 1
                else:
                    self.logger.debug("{} is dictionary. Iterating.".format(frkey))
                    matchtype = self.__is_match_dict(subrule[key], framedict[frkey])
            else:
                matchtype = -1
            self.logger.debug("matchtype: {}".format(matchtype))
        return matchtype

    def __apply_rule(self, rule, frame):
        '''
        Checks whether the frame matches the current rule.
        Iterates the rule and the frame to see if the frame contains the parameters defined in the rule and if the value
        of these parameters match.
        :param frame: dictionary with the content of a wireshark frame.
        :return: ismatch -> true if the packet matches the current rule
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
                matchtype = self.__is_match_dict(subrule, frame[protocol])
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
            self.logger.info("Frame {} matches rule {}!!!".format(self.__current_frame_index, self.__current_rule_index))
            self.logger.debug("Now, search \"store\" section.")
            if "store" in rule:
                self.__parse_store_fields(rule["store"], frame)
            if "report" in rule :  # report only if rule is matched
                self.__build_rule_report(rule["report"])
        return ismatch

    def __build_rule_report(self, rulereports):
        '''
        Builds the report for a rule.
        Performs variable substitution where required.
        '''
        for rulereport in rulereports:
            assert("tag" in rulereport)
            assert ("value" in rulereport)
            search_var = re.search("{{(.*)}}", rulereport["value"])
            if (search_var):
                var_name = search_var.group(1)
                self.logger.debug("Found variable to replace {}".format(var_name))
                assert (var_name in self.__tcvars), "{} not stored.".format(var_name)
                if type(self.__tcvars[var_name]) is list:
                    report_value = "{}".format(self.__tcvars[var_name])
                else:
                    report_value = self.__tcvars[var_name]
                rulereport["value"] = re.sub("{{(.*)}}", report_value, rulereport["value"])
                self.logger.debug("{} set to value {}".format("value", rulereport["value"]))
            self.__report.add_to_current_rule(rulereport["tag"], rulereport["value"])

    def __iter_frame_for_store_fields(self, storedict, framedict):
        '''
        Iterates the keys in "storedict" inside framedict until its final value. For example, in the following:
        "msg_hdr_tree": {
                "callId": "Call-ID"
            }
        it iterates inside "msg_hdr_tree" until it finds "callId". Since "callId" is not a dict, it stops there.

        :param storedict: dictionary from inside "store" object of a rule. Must contains a single key.
        :param framedict: dictionary from a frame
        :return: Value of the field iterated if it exists. None otherwise.
        '''
        keys = list(storedict.keys())
        self.logger.debug("Keys: {}".format(keys))
        field = None
        value = None
        if len(keys) > 0:
            frkey = keys[0]
            self.logger.debug("Iteration for frkey: {}".format(frkey))
            if frkey in framedict:  # check that the key exists in the frame
                self.logger.debug("frkey: {} is a {}".format(frkey, type(framedict[frkey])))
                if type(framedict[frkey]) is dict:
                    field, value = self.__iter_frame_for_store_fields(storedict[keys[0]], framedict[frkey])
                elif type(framedict[frkey]) is list:
                    for listitem in framedict[frkey]:
                        self.logger.debug("listitem  type: {}".format(type(listitem)))
                        self.logger.debug("listitem: {}".format(listitem))
                        if type(listitem) is dict:
                            fld, val = self.__iter_frame_for_store_fields(storedict[keys[0]], listitem)
                            if val is not None:
                                if value is None:
                                    self.logger.debug("value set to: {}".format(val))
                                    value = val
                                elif type(value) is list:
                                    self.logger.debug("Appending {} to {}".format(val, value))
                                    value.append(val)
                                else:
                                    value = [value]
                                    self.logger.debug("Converted to list {} and appending {}".format(value, val))
                                    value.append(val)
                            if fld is not None:
                                field = fld
                        else:
                            field = storedict[keys[0]]
                            value = framedict[frkey]
                            self.logger.debug("variable is a list of values {}".format(value))
                        self.logger.debug("Output list {}".format(value))
                elif value is not None:
                    values = list()
                    values.append(value)
                    field = storedict[keys[0]]
                    values.append(framedict[frkey])
                    value = values
                    self.logger.debug("variable is a list of values {}".format(value))
                else:
                    field = storedict[keys[0]]
                    value = framedict[frkey]
                    self.logger.debug("variable {} set to value {}".format(field, value))
            else:
                self.logger.debug("No Key: {} in frame ".format(frkey))
        else:
            self.logger.debug("Empty dictionary")
        self.logger.debug("Return field {} with value {}".format(field, value))
        return field, value


    def __parse_store_fields(self, store, frame):
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
                key, value = self.__iter_frame_for_store_fields(item, frame[protocol])
                if (key is not None):
                    # store the value for future use
                    self.logger.debug("Storing key {} with value {}".format(key, value))
                    if (value is None):
                        self.__tcvars[key] = ""
                    else:
                        self.__tcvars[key] = value


    def __iter_rule_for_vars(self, tempdict):
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
                        assert (var_name in self.__tcvars), "{} not stored.".format(var_name)
                        tempdict[key] = re.sub("{{(.*)}}", self.__tcvars[var_name], tempdict[key])
                        self.logger.debug("{} set to value {}".format(key, tempdict[key]))
            else:
                self.logger.debug("{}".format("{} is a dictionary. New iteration.".format(key)))
                self.__iter_rule_for_vars(tempdict[key])


    def __apply_stored_variables(self, rule):
        '''
        Searches the rule for variables (inside double brackets {{}}) and replaces them with the stored
        value, if it exists. If it does not exist, then raises an exception.
        :param rule: index of the rules to which variables shall be set.
        :return: void . Raises exception if variable does no exist.
        '''
        assert ("match" in rule), "Invalid rule. Nothing to match."
        self.logger.debug("Rule to iterate to apply stored variables\n{}".format(rule["match"]))
        for protocol in rule["match"]:
            self.logger.debug("Iterating protocol {} for variable replacement".format(protocol))
            subrule_index = 0
            for subrule in rule["match"][protocol]:
                self.logger.debug("Iterating subrule {} for variable replacement".format(subrule_index))
                self.__iter_rule_for_vars(subrule)
                subrule_index += 1

