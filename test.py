#!/usr/bin/env python

import os
import sys
import logging
from tcparser import trace
from tcparser import test_case

LOGLEVEL = logging.DEBUG  # DEBUG, INFO, WARNING, ERROR or CRITICAL
LOGFORMAT = "%(levelname)-9s[%(filename)s:%(lineno)s - %(funcName)s()] %(message)s"

def usage():
    '''
    Prints usage
    :return:
    '''
    print("Usage: test <template_file> <trace_file>")
    print("\t<template_file>\tTemplate file for Test Cas")
    print("\t<trace_file>\tJSON trace file obtained from Wireshark.")
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        usage()

    logging.basicConfig(filename=os.path.join(os.getcwd(), "logs", "WsTraceAnalyser.log"), filemode='w',
                        level=LOGLEVEL,
                        format=LOGFORMAT)
    logger = logging.getLogger("TraceAnaliser")
    logger.info('Logging started ...')
    trace = trace.Trace(sys.argv[2])
    test_case = test_case.TestCase(sys.argv[1], trace)
    test_case.run()
    logger.info("Test Case Result: {}".format(test_case.get_result()))
    print("Test Case Result: {}".format(test_case.get_result()))
