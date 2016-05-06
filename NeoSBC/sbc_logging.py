import logging
import string, sys, re
import pprint

__author__ = 'jkinney'


class Logging():
    def __init__(self):
        self.pp = pprint.PrettyPrinter(indent=4)

    def LogStr(self, level, report_string, instring):
        print "***%s: %s" % (level, report_string)
        print "%s" % instring
        print "***"

    def LogSIP(self, level, report_string, sip_message):  # Log a SIP Message
        print "***%s: %s" % (level, report_string)
        print "%s" % sip_message
        print "***"

    def LogDict(self, level, report_string, dict):  # Log a Pretty version of a Dictionary
        print "***%s: %s" % (level, report_string)
        self.pp.pprint(dict)
        print "***"

    def LogCall(self, level, report_string, call_record):

        frag_index = 0
        temp_call = {}

        for key in call_record.keys():
            if key is not 'fragments':
                temp_call[key] = call_record[key]

        self.LogDict(level, report_string + " Call Info", temp_call)

        fragments = call_record['fragments']

        for fragment in fragments:
            self.LogDict(level, report_string + " Call Fragment:" + str(frag_index), fragment)
            frag_index += 1
