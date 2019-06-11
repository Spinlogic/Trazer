'''
This class is used for reporting test cases.
Reporting instructions are red from the TC template and written into an instance of this class.

A report for a TC is JSON object with the following structure:

{
  "metadata": {TC metadata},
  "rules": [
    {
      "metadata": {same as dict metadata inside TC template},
      tag: value(s)
    }
    ...
  ]
}

The name and value of the tag is taken from the "report" dict inside the TC description.
Each dict inside "rules" correspond to a dict inside "template" of TC description.
'''
import logging
import json

class TcReport():

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.__report = {}
        self.__report["result"] = "Fail"
        self.__report["rules"] = []
        self.current_rule = -1

    def new_rule(self, metadata: dict = None):
        self.current_rule += 1
        self.__report["rules"].append({})
        self.__report["rules"][self.current_rule]["metadata"] = metadata
        self.__report["rules"][self.current_rule]["result"] = "Failed"

    def set_result_of_current_rule(self, result: bool, isoptional: bool = False):
        '''
        Set the result of this rule
        :param result: True = Passed, False = Failed
        :param isoptional: True = Matching this rule is optional, False = matching this rule is required
        :return:
        '''
        self.__report["rules"][self.current_rule]["optional"] = isoptional
        if result:
            self.__report["rules"][self.current_rule]["result"] = "Passed"
        else:
            self.__report["rules"][self.current_rule]["result"] = "Failed"

    def add_to_current_rule(self, tag, value):
        self.__report["rules"][self.current_rule][tag] = value

    def set_field(self, tag: str, value):
        self.__report[tag] = value

    def set_result(self, result):
        '''
        Set the result of this TC
        :param result:  True = Passed, False = Failed
        :return:
        '''
        if result:
            self.__report["result"] = "Passed"
        else:
            self.__report["result"] = "Failed"
        
    def save_report_to_file(self, filepath):
        with open(filepath, "w") as fp:
            return json.dump(self.__report, fp, indent=3)
    
    