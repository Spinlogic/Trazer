'''
Implements TC template functionality
'''

import re
import logging


class TestTemplate(object):

    def __init__(self, template):
        self.logger = logging.getLogger(__name__)
        self.template = template
        self.current_rule_index = -1


    def get_rule(self, index):
        assert(index < len(self.template))
        return self.template[index]


    def get_next_rule_index(self):
        '''
        Gets the index of the next rule inside the template.
        :return:
        '''
        self.current_rule_index += 1
        if(self.current_rule_index >= len(self.template)):
            return -1
        return self.current_rule_index
