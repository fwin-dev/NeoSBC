import logging
import re


__author__ = 'jkinney'

# Lexical analyze for security rules
def parse_rule(security_rule_list, rule):

    # TODO fix to match code and syntax
    # -1 = lexical error
    # 0 = Start
    # 1 = Found type
    # 2 = In test Destination
    # 3 = From Zone
    # 4 = To Zone
    # 5 = URI reformat
    # 6 = Destination SIP UA
    rule_state = 0

    # TODO Add "from" token, to indicate a source IP or contact domain for screening

    pos = 0
    pattern = re.compile("\s*(permit for|deny for|sip:|on|to|as|using|(\w+)|(.))")
    rule_name, rule_string = rule
    rule_fragment = {'rule_name': rule_name}
    destination_string = ""
    seczone_string = ""
    ruri_string = ""
    destination_list = []

    while 1:
        match_token = pattern.match(rule_string, pos)
        if not match_token:
            # May need to finish up our seczone string from a deny rule
            if rule_state == 11:
                rule_fragment['from_seczone'] = seczone_string
            break

        # TODO need to finish parsing and statemachine for "using IP:PORT"

        # States need to be in reverse order so that match happens as the rule analysis continues
        if rule_state == 4:
            if match_token.group(match_token.lastindex) != "using":
                ruri_string += match_token.group(match_token.lastindex)
            else:
                rule_fragment['uri_pattern'] = ruri_string
                rule_state = 5

        if rule_state == 3:
            if match_token.group(match_token.lastindex) != "as":
                seczone_string += match_token.group(match_token.lastindex)
            else:
                rule_fragment['to_seczone'] = seczone_string
                seczone_string = ""
                rule_state = 4

        if rule_state == 2:
            if match_token.group(match_token.lastindex) != "to":
                seczone_string += match_token.group(match_token.lastindex)
            else:
                rule_fragment['from_seczone'] = seczone_string
                seczone_string = ""
                rule_state = 3

        if rule_state == 11:
            seczone_string += match_token.group(match_token.lastindex)

        if rule_state == 1 or rule_state == 10:
            if match_token.group(match_token.lastindex) == "or":
                destination_list.append(destination_string)
                destination_string = ""
            elif match_token.group(match_token.lastindex) != "on":
                destination_string += match_token.group(match_token.lastindex)
            else:
                destination_list.append(destination_string)
                rule_fragment['destination_list'] = destination_list
                if rule_fragment['rule_type'] == "permit":
                    rule_state = 2
                else:
                    rule_state = 11

        if rule_state == 0:
            if match_token.group(match_token.lastindex) == "permit for":
                rule_fragment.update({'rule_type': 'permit'})
                rule_state = 1
            elif match_token.group(match_token.lastindex) == "deny for":
                rule_fragment.update({'rule_type': 'deny'})
                rule_state = 10
            else:
                rule_state = -1  # We had an unexpected first token
                break

        pos = match_token.end()

    security_rule_list.append(rule_fragment)
