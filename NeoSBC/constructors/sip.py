import logging
#!/usr/bin/env python

# Author: Mark Boger

# Sip Method Types
ACK         = 'ACK'
BYE         = 'BYE'
CANCEL      = 'CANCEL'
INFO        = 'INFO'
INVITE      = 'INVITE'
MESSAGE     = 'MESSAGE'
NOTIFY      = 'NOTIFY'
OPTIONS     = 'OPTIONS'
PRACK       = 'PRACK'
PUBLISH     = 'PUBLISH'
REFER       = 'REFER'
REGISTER    = 'REGISTER'
SUBSCRIBE   = 'SUBSCRIBE'
UPDATE      = 'UPDATE'

class sip_constructor():
    """ Construct sip messages to test the sbc """
    def __init__( self, sip_type=REGISTER ):
        self.type = sip_type;

    def construct( self ):
        self.sip_message =\
"""
{method} {request_uri}
Via: SIP/2.0/UDP {sent_by};branch=z9hG4bK{branch}
Max-Forwards: {max_forwards}
To: {recipient_aor}{to_tag}
From: {sender_aor}{sender_tag}
Call-ID: {call_id}
CSeq: {seq!s} {method}
Contact: {sip_uri}
Content-Type: {content_type}
Content-Length: {length}
""".format( method=self.type, request_uri='test', sent_by='test',
            branch='test', max_forwards=32, recipient_aor='test',
            to_tag='', sender_aor='test', sender_tag=1234,
            call_id='test', seq=1234, sip_uri='test',
            content_type='test', length=3 ).strip()

        return self.sip_message

if __name__ == "__main__":
    a = sip_constructor(sip_type=INVITE)
    test = a.construct()
    print test

