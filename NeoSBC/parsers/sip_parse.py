import logging
import re


# SIP Parsing Classes. These are classes intended to help with manipulating the primitives used in SIP messaging.
# Heavy use of regular expression to put a high level spin on parsing that take aways room from buffer and other error
# The regular expression is hard coded into class and only the parsed string is injected and the SIP message parser will
# do some sanity checking on lengths and related for more safety.

# TODO Need to put any failure to parse a header into the error-info header in forwarded message,
# TODO no value, but header name is indicated

# TODO Big todo, go back and refine the regular expressions used in some headers.
# TODO URI, Address and Attributes class are needed, these break down each in easy to handle pieces.
# TODO Finish API document for each class, at least the expected exposed ones initially
# Used to test for a Request and parse the line for usable attributes

# The following headers are not fully implemented yet, all were taken from RFC-3261
# Probably need to get most of these supported, a good SBC doesn't need to pass them all by default
# but should be able to if needed. At this point an unrecognized header is parsed as a string
# the value is placed in header_value
# Accept, 20.1
# Accept-Encoding, 20.2
# Accept-Language, 20.3
# Alert-Info, 20.4
# Authentication-Info, 20.6
# Authorization, 20.7
# Content-Disposition, 20.11
# Content-Encoding, 20.12
# Content-Language, 20.13
# Date, 20.17
# Error-Info, 20.18
# Expires, 20.19
# In-Reply-To, 20.21
# Min-Expires, 20.23
# MIME-Version, 20.24
# Organization, 20.25
# TODO Priority, 20.26
# Proxy-Authenticate, 20.27
# Proxy-Authorization, 20.28
# Proxy-Require, 20.29
# Reply-To, 20.31
# TODO Require, 20.32
# Retry-After, 20.33
# TODO Route, 20.34
# TODO Server, 20.35
# TODO Subject, 20.36
# Timestamp, 20.38
# TODO Unsupported, 20.40
# Warning, 20.43
# WWW-Authenticate, 20.44

logger = logging.getLogger( 'sipLogger' )

class RequestLine(object):

    # For now we only support SIP 2.0, so why mess with prot/ver
    __syntax = re.compile("^(?P<method>[A-Z]*) (?P<uri>.*) SIP/2.0$")

    logger = logging.getLogger( 'sipLogger.sip_parse.RequestLine' )

    def __init__(self, value=''):
        if value:
            rematches = RequestLine.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP Request Line(' + value + ')')
            self.method, self.uri = rematches.groups()
            self.type = 'REQUEST'
        else:
            self.method = None
            self.uri = None
            self.type = "UNKNOWN"
        logger.debug( 'Type: {} Method: {} Uri: {}'.format( self.type, self.method, self.uri ) )

    def __repr__(self):
        return self.method + " " + self.uri + " " + "SIP/2.0"

    def from_dict(self, indict):  #
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking method' )
        if 'method' in indict.keys():
            self.method = indict['method']
        logger.info( 'Checking method uri' )
        if 'uri' in indict.keys():
            self.uri = indict['uri']
        logger.info( 'Cheking type' )
        if 'type' in indict.keys():
            self.uri = indict['type']

    def dup(self):
        return RequestLine(self.__repr__())


# Used to test for a Response and parse the line for usable attributes
class ResponseLine(object):

    __syntax = re.compile("^SIP/2.0 (?P<code>[0-9]{3}) (?P<text>.*)")

    logger = logging.getLogger( 'sipLogger.sip_parse.ResponseLine' )

    def __init__(self, value=''):
        if value:
            rematches = ResponseLine.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP Response Line(' + value + ')')
            self.code, self.text = rematches.groups()
            self.type = 'RESPONSE'
        else:
            self.code = None
            self.text = None
            self.type = 'UNKNOWN'
        logger.debug( 'Code: {} Text: {} Type: {}'.format( self.code, self.text, self.type ) )


    def __repr__(self):
        return "SIP/2.0" + " " + self.code + " " + self.text

    def from_dict(self, indict):  #
        #  TODO Make more resilient, like throwing an exception
        # Make sure to check that this is actually doing what we want
        logger.info( 'Checking code' )
        if 'code' in indict.keys():
            self.method = indict['code']
        logger.info( 'Checking text' )
        if 'text' in indict.keys():
            self.uri = indict['text']
        logger.cinf( 'Checking type' )
        if 'type' in indict.keys():
            self.uri = indict['type']

    def dup(self):
        return ResponseLine(self.__repr__())


class URIParameters(object):

    logger = logging.getLogger( 'sipLogger.sip_parse.URIParameters' )
    def __init__(self, value=''):
        if value:
            splits = map(lambda n: n.partition('='), value.split(';')) if value else []
            self.param = dict(map(lambda k: (k[0], k[2] if k[2] else None), splits)) if splits else {}
        else:
            self.param = {}
        logger.debug( 'Params: {}'.format( self.param ) )

# Base Class for getting a header value string
class HeaderStrValueOnly(object):

    __syntax = re.compile("^(?P<header_value>.*)$")
    logger = logging.getLogger( 'sipLogger.sip_parse.HeaderStrValueOnly' )

    def __init__(self, value=''):
        if value:
            rematches = HeaderStrValueOnly.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid String Value Header(' + value + ')')
            self.header_value = rematches.groups()[0]
        else:
            self.header_value = None
        logger.debug( 'Header value: {}'.format( self.header_value ) )

    def __repr__(self):
        return self.header_value

    def from_dict(self, indict):  #
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking the header value' )
        if 'header_value' in indict.keys():
            self.header_value = indict['header_value']


    def dup(self):
        return HeaderStrValueOnly(self.__repr__())


# Base Class for getting a header value string
class HeaderIntValueOnly(object):

    __syntax = re.compile("^(?P<header_value>[0-9]*)$")
    logger = logging.getLogger( 'sipLogger.sip_parse.HeaderIntValueOnly' )

    def __init__(self, value=''):
        if value:
            rematches = HeaderIntValueOnly.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid String Value Header(' + value + ')')
            self.header_value = int(rematches.groups()[0])
        else:
            self.header_value = None
        logger.debug( 'Header Value: {}'.format( self.header_value ) )

    def __repr__(self):
        return str(self.header_value)

    def from_dict(self, indict):  #
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking header value' )
        if 'header_value' in indict.keys():
            self.header_value = indict['header_value']

    def dup(self):
        return HeaderStrValueOnly(self.__repr__())


class RecordRoute(object):

    # TODO Need to research about the <> around URI, it is optional in some cases, but maybe not in these headers
    # TODO right now I am enforcing it
    __syntax = re.compile("^<(?P<uri>.*)>$")

    logger = logging.getLogger( 'sipLogger.sip_parse.RecordRoute' )
    def __init__(self, value=''):
        if value:
            rematches = RecordRoute.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP Record-Route Header(' + value + ')')
            self.uri = rematches.groups()[0]
        else:
            self.uri = None
        logger.debug( 'Uri: {}'.format( self.uri ) )

    def __repr__(self):  # <sip:192.168.56.172:8080;transport=ws;r2=on;lr=on>
        return "<" + self.uri + ">"

    def from_dict(self, indict):  #
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking the uri' )
        if 'uri' in indict.keys():
            self.uri = indict['uri']

    def dup(self):
        return RecordRoute(self.__repr__())


# Used to parse the Via line(s)
class Via(object):

    __syntax = re.compile("^SIP/2.0/(?P<transport>[A-Z]*) "
                          + "(?:(?:(?P<host>[^;\?:]*)(?::(?P<port>[\d]+))?))"
                          + "(?:;(?P<attributes>[^\?]*))?$")

    logger = logging.getLogger( 'sipLogger.sip_parse.Via' )
    def __init__(self, value=''):
        if value:
            rematches = Via.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP Via Header(' + value + ')')
            self.transport, self.host, self.port, self.attributes = rematches.groups()
        else:
            self.transport = None
            self.host = None
            self.port = None
            self.attributes = None
        logger.debug( 'Transport: {} Host: {} Port:{} Attributes:{}'.format( self.transport, self.host, self.port, self.attributes ) )

    def __repr__(self):  # SIP/2.0/UDP 192.168.56.172;branch=z9hG4bK743e.754a77de8a101e546ed5da9c75b990ff.0
        return "SIP/2.0/" + self.transport.upper() + " " + (self.host + ":" +
                                                            self.port if self.port else self.host) + \
               (";" + self.attributes if self.attributes else "")

    def from_dict(self, indict):  #
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking transport' )
        if 'transport' in indict.keys():
            self.transport = indict['transport']
        logger.info( 'Checking host' )
        if 'host' in indict.keys():
            self.host = indict['host']
        logger.info( 'Checking port' )
        if 'port' in indict.keys():
            self.port = indict['port']
        logger.info( 'Checking attributes' )
        if 'attributes' in indict.keys():
            self.attributes = indict['attributes']

    def dup(self):
        return Via(self.__repr__())


# Puts the value into an integer for needed math, still returns a string for header creation
class MaxForwards(object):

    __syntax = re.compile("^(?P<max_forwards>[0-9]*)$")

    logger = logging.getLogger( 'sipLogger.sip_parse.MaxForwards' )
    def __init__(self, value=''):
        if value:
            rematches = MaxForwards.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP Max-Forwards Header(' + value + ')')
            self.max_forwards = int(rematches.groups()[0])
        else:
            self.max_forwards = None
        logger.debug( 'MaxForwards: {}'.format( self.max_forwards ) )

    def __repr__(self):  # 16
        return str(self.max_forwards)

    def from_dict(self, indict):  #
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking the max_forwards' )
        if 'max_forwards' in indict.keys():
            self.max_forwards = indict['max_forwards']

    def dup(self):
        return MaxForwards(self.__repr__())


# TODO ***Need to break apart the friendly name, uri and attributes
class From(object):

    __syntax = re.compile("^(?P<uri>.*)$")

    logger = logging.getLogger( 'sipLogger.sip_parse.From' )
    def __init__(self, value=''):
        if value:
            rematches = From.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP From Header(' + value + ')')
            self.uri = rematches.groups()[0]
            self.name = None
            self.attributes = None
        else:
            self.name = None
            self.uri = None
            self.attributes = None
        logger.debug( 'Name: {} Uri: {} Attributes: {}'.format( self.name, self.uri, self.attributes ) )

    def __repr__(self):  # <sip:example@example.org>;tag=i848d65132
        return self.uri

    def from_dict(self, indict):  # {'uri': '<sip:example@example.org>;tag=749alelmr0'}
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking name' )
        if 'name' in indict.keys():
            self.name = indict['name']
        logger.info( 'Checking uri' )
        if 'uri' in indict.keys():
            self.uri = indict['uri']
        logger.info( 'Checking attributes' )
        if 'attributes' in indict.keys():
            self.attributes = indict['attributes']

    def dup(self):
        return From(self.__repr__())


# TODO ***Need to break apart the friendly name, uri and attributes
class To(object):

    __syntax = re.compile("^(?P<uri>.*)$")

    logger = logging.getLogger( 'sipLogger.sip_parse.To' )
    def __init__(self, value=''):
        if value:
            rematches = To.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP To Header(' + value + ')')
            self.uri = rematches.groups()[0]
            self.name = None
            self.attributes = None
        else:
            self.name = None
            self.uri = None
            self.attributes = None
        logger.debug( 'Name: {} Uri: {} Attributes: {}'.format( self.name, self.uri, self.attributes ) )

    def __repr__(self):  # <sip:example@10.0.0.1>
        return self.uri

    def from_dict(self, indict):  # {'uri': '<sip:example@example.org>;tag=749alelmr0'}
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking name' )
        if 'name' in indict.keys():
            self.name = indict['name']
        logger.info( 'Checking uri' )
        if 'uri' in indict.keys():
            self.uri = indict['uri']
        logger.info( 'Checking attributes' )
        if 'attributes' in indict.keys():
            self.attributes = indict['attributes']

    def dup(self):
        return To(self.__repr__())


# TODO ***Need to break apart the friendly name, uri and attributes
class Contact(object):

    __syntax = re.compile("^(?P<uri>.*)$")

    logger = logging.getLogger( 'sipLogger.sip_parse.Contact' )
    def __init__(self, value=''):
        if value:
            rematches = Contact.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP Contact Header(' + value + ')')
            self.uri = rematches.groups()[0]
            self.name = None
            self.attributes = None
        else:
            self.name = None
            self.uri = None
            self.attributes = None
        logger.debug( 'Name: {} Uri: {} Attributes: {}'.format( self.name, self.uri, self.attributes ) )

    def __repr__(self):  # <sip:i70likmv@lm3tqro83ime.invalid;alias=192.168.56.1~51803~5;transport=ws;ob>;audio;video;text;data;+croc.sdkversion="<1>"
        return self.uri

    def from_dict(self, indict):  # {'uri': '<sip:example@example.org>;tag=749alelmr0'}
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking name' )
        if 'name' in indict.keys():
            self.name = indict['name']
        logger.info( 'Checking uri' )
        if 'uri' in indict.keys():
            self.uri = indict['uri']
        logger.info( 'Checking attributes' )
        if 'attributes' in indict.keys():
            self.attributes = indict['attributes']

    def dup(self):
        return Contact(self.__repr__())


class CallID(object):

    __syntax = re.compile("^(?P<call_id>.*)$")

    logger = logging.getLogger( 'sipLogger.sip_parse.CallID' )
    def __init__(self, value=''):
        if value:
            rematches = CallID.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP Call-ID Header(' + value + ')')
            self.call_id = rematches.groups()[0]
        else:
            self.call_id = None
        logger.debug( 'Call ID: {}'.format( self.call_id ) )

    def __repr__(self):  # tvkrrelrrg8i09eei7t7
        return self.call_id

    def from_dict(self, indict):  # {'uri': '<sip:example@example.org>;tag=749alelmr0'}
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking Call ID' )
        if 'call_id' in indict.keys():
            self.call_id = indict['call_id']

    def dup(self):
        return CallID(self.__repr__())


class CSeq(object):

    __syntax = re.compile("^(?P<sequence_number>[0-9]*) (?P<method>[A-Z]*)$")

    logger = logging.getLogger( 'sipLogger.sip_parse.CSeq' )
    def __init__(self, value=''):
        if value:
            rematches = CSeq.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP CSeq Header(' + value + ')')
            self.sequence_number = int(rematches.groups()[0])
            self.method = rematches.groups()[1]
        else:
            self.sequence_number = None
            self.method = None
        logger.debug( 'Sequence Number: {} Method: {}'.format( self.sequence_number, self.method ) )

    def __repr__(self):  # 3882 INVITE
        return str(self.sequence_number) + " " + self.method

    def from_dict(self, indict):  # {'uri': '<sip:example@example.org>;tag=749alelmr0'}
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking sequence_number' )
        if 'sequence_number' in indict.keys():
            self.sequence_number = indict['sequence_number']
        logger.info( 'Checking method' )
        if 'method' in indict.keys():
            self.method = indict['method']

    def dup(self):
        return CSeq(self.__repr__())


# SIP Allow Header
# RFC-3261, section 20.5
# Parses Allow header and produces python list of values
# This method produces a header string looking like that in RFC-3261, where spaces are after the comma.
#
# From RFC-3261:
#
# Example:
#     Allow: INVITE, ACK, OPTIONS, CANCEL, BYE

class Allow(object):

    __syntax = re.compile("^(?P<allow_list>[-\w\s]+(?:,[-\w\s]*)*)$")

    logger = logging.getLogger( 'sipLogger.sip_parse.Allow' )
    def __init__(self, value=''):
        if value:
            rematches = Allow.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP Allow Header(' + value + ')')
            self.allow_list = [method.strip(' ') for method in (str(rematches.groups()[0]).split(","))]
        else:
            self.allow_list = None
        logger.debug( 'Allow list: {}'.format( self.allow_list ) )

    def __repr__(self):  # ACK,CANCEL,BYE,OPTIONS,NOTIFY,INVITE,UPDATE,REFER
        return str(", ").join(self.allow_list)

    def from_dict(self, indict):  # {'uri': '<sip:example@example.org>;tag=749alelmr0'}
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking allow_list' )
        if 'allow_list' in indict.keys():
            self.allow_list = indict['allow_list']

    def dup(self):
        return Allow(self.__repr__())


# SIP Call-Info
# RFC-3261, section 20.9
# Parse Call-Info header and produces list of items
#
# From RFC-3261:
#
# Example:
#
#   Call-Info: <http://wwww.example.com/alice/photo.jpg> ;purpose=icon,<http://www.example.com/alice/> ;purpose=info

class CallInfo(object):

    __syntax = re.compile("^(?P<call_info_list>.*)$")

    logger = logging.getLogger( 'sipLogger.sip_parse.CallInfo' )
    def __init__(self, value=''):
        if value:
            rematches = CallInfo.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP Call-Info Header(' + value + ')')
            self.call_info_list = [method.strip(' ') for method in (str(rematches.groups()[0]).split(","))]
        else:
            self.call_info_list = None
        logger.debug( 'Call info list: {}'.format( self.call_info_list ) )

    def __repr__(self):  # <http://wwww.example.com/alice/photo.jpg> ;purpose=icon,<http://www.example.com/alice/> ;purpose=info
        return str(", ").join(self.call_info_list)

    def from_dict(self, indict):  # {'uri': '<sip:example@example.org>;tag=749alelmr0'}
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking call_info_list' )
        if 'call_info_list' in indict.keys():
            self.call_info_list = indict['call_info_list']

    def dup(self):
        return CallInfo(self.__repr__())

# SIP Supported
# RFC-3261, section 20.37
# Parse Supported header
#
# From RFC-3261
#
# Example:
#
#      Supported: 100rel

class Supported(object):

    __syntax = re.compile("^(?P<supported_list>[-\w\s]+(?:,[-\w\s]*)*)$")

    logger = logging.getLogger( 'sipLogger.sip_parse.Supported' )
    def __init__(self, value=''):
        if value:
            rematches = Supported.__syntax.match(value)
            if not rematches:
                raise ValueError('Invalid SIP Supported Header(' + value + ')')
            self.supported_list = [method.strip(' ') for method in (str(rematches.groups()[0]).split(","))]
        else:
            self.supported_list = None
        logger.debug( 'Supported list: {}'.format( self.supported_list ) )

    def __repr__(self):  # path,outbound,gruu,tdialog
        return str(", ").join(self.supported_list)

    def from_dict(self, indict):  # {'uri': '<sip:example@example.org>;tag=749alelmr0'}
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking supported_list' )
        if 'supported_list' in indict.keys():
            self.supported_list = indict['supported_list']

    def dup(self):
        return Supported(self.__repr__())


# SIP User-Agent
# RFC-3261, section 20.41
# Parse User-Agent header
#
# From RFC-3261
#
# Example:
#
#      User-Agent: Softphone Beta1.5

class UserAgent(HeaderStrValueOnly):

    logger = logging.getLogger( 'sipLogger.sip_parse.UserAgent' )
    def __init__(self, value=''):
        super(UserAgent, self).__init__(value)  # Let the super do the parsing
        self.user_agent = self.header_value  # Assign our parsed value to our class variable
        del self.header_value  # Remove unused variables after processing
        #del self.rematches  # Remove unused variables after processing
        logger.debug( 'User Agent: {}'.format( self.user_agent ) )

    def __repr__(self):  # 'application/sdp'
        return self.user_agent

    def from_dict(self, indict):  # {'uri': '<sip:example@example.org>;tag=749alelmr0'}
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking user_agent' )
        if 'user_agent' in indict.keys():
            self.user_agent = indict['user_agent']

    def dup(self):
        return UserAgent(self.__repr__())


# SIP Content-Type
# RFC-3261, section 20.15
# Parse Content-Type
#
# From RFC-3261
#
# Examples:
#
#      Content-Type: application/sdp
#      c: text/html; charset=ISO-8859-4

class ContentType(HeaderStrValueOnly):

    logger = logging.getLogger( 'sipLogger.sip_parse.ContentType' )
    def __init__(self, value=''):
        super(ContentType, self).__init__(value)  # Let the super do the parsing
        self.content_type = self.header_value  # Assign our parsed value to our class variable
        del self.header_value  # Remove unused variables after processing
        #del self.rematches  # Remove unused variables after processing
        logger.debug( 'Content Type: {}'.format( self.content_type ) )

    def __repr__(self):  # 'application/sdp'
        return self.content_type

    def from_dict(self, indict):  # {'uri': '<sip:example@example.org>;tag=749alelmr0'}
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking content_type' )
        if 'content_type' in indict.keys():
            self.content_type = indict['content_type']


# SIP Content-Length
# RFC-3261, section
# Puts the value into an integer for needed math, still returns a string for header creation
#
# From RFC-3261
#
# Examples:
#
#      Content-Length: 349
#      l: 173

class ContentLength(HeaderIntValueOnly):

    logger = logging.getLogger( 'sipLogger.sip_parse.ContentLength' )
    def __init__(self, value=''):
        super(ContentLength, self).__init__(value)  # Let the super do the parsing
        self.content_length = self.header_value
        del self.header_value  # Remove unused variables after processing
        #del self.rematches  # Remove unused variables after processing
        logger.debug( 'Content Length: {}'.format( self.content_length ) )

    def __repr__(self):  # 349
        return str(self.content_length)

    def from_dict(self, indict):  # {'uri': '<sip:example@example.org>;tag=749alelmr0'}
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking content_length' )
        if 'content_length' in indict.keys():
            self.content_length = indict['content_length']


# SIP Unknown Header
# RFC-3261, section
# Puts the value into a String since we don't know it
#

class UnknownHeader(HeaderStrValueOnly):

    logger = logging.getLogger( 'sipLogger.sip_parse.UnknownHeader' )
    def __init__(self, value=''):
        logger.debug( 'UnkownHeader called' )
        super(UnknownHeader, self).__init__(value)  # Let the super do the parsing
        #del self.rematches  # Remove unused variables after processing
        logger.debug( 'Backing in UnknownHeader' )

    def __repr__(self):  # 349
        return str(self.header_value)

    def from_dict(self, indict):  # {'uri': '<sip:example@example.org>;tag=749alelmr0'}
        #  TODO Make more resilient, like throwing an exception
        logger.info( 'Checking header_value' )
        if 'header_value' in indict.keys():
            self.header_value = indict['header_value']

class SIPParser(object):

    __header_syntax = re.compile("^(?P<header>.*): (?P<value>.*)$")

    # Command Pattern used to match a header up to it's equivalent class
    parser_dictionary = {
        'Accept': UnknownHeader,
        'Accept-Encoding': UnknownHeader,
        'Accept-Language': UnknownHeader,
        'Alert-Info': UnknownHeader,
        'Authentication-Info': UnknownHeader,
        'Authorization': UnknownHeader,
        'Content-Disposition': UnknownHeader,
        'Content-Encoding': UnknownHeader,
        'Content-Language': HeaderStrValueOnly,
        'Date': UnknownHeader,
        'Error-Info': UnknownHeader,
        'Expires': UnknownHeader,
        'In-Reply-To': UnknownHeader,
        'Min-Expires': UnknownHeader,
        'MIME-Version': UnknownHeader,
        'Organization': UnknownHeader,
        'Proxy-Authenticate': UnknownHeader,
        'Proxy-Authorization': UnknownHeader,
        'Proxy-Require': UnknownHeader,
        'Reply-To': UnknownHeader,
        'Retry-After': UnknownHeader,
        'Timestamp': UnknownHeader,
        'Warning': UnknownHeader,
        'WWW-Authenticate': UnknownHeader,
        'Record-Route': RecordRoute,
        'Via': Via,
        'From': From,
        'Max-Forwards': MaxForwards,
        'To': To,
        'Contact': Contact,
        'Call-ID': CallID,
        'Call-Info': CallInfo,
        'Content-Length': ContentLength,
        'Content-Type': ContentType,
        'CSeq': CSeq,
        'User-Agent': UserAgent
    }

    # Used to do sanity checking on an Inbound or outbound request
    request_required_dictionary = {
        'INVITE': ['Call-ID', 'CSeq', 'From', 'To', 'Max-Forwards'],
        'ACK': ['Call-ID', 'CSeq', 'From', 'To', 'Max-Forwards'],
        'BYE': ['Call-ID', 'CSeq', 'From', 'To', 'Max-Forwards'],
        'CANCEL': ['Call-ID', 'CSeq', 'From', 'To', 'Max-Forwards'],
        'OPTIONS': ['Call-ID', 'CSeq', 'From', 'To', 'Max-Forwards'],
        'REGISTER': ['Call-ID', 'CSeq', 'From', 'To', 'Max-Forwards']
    }

    response_required_dictionary = {
        'XXX': ['CSeq', 'From', 'To'],
        '1XX': ['CSeq', 'From', 'To'],
        '2XX': ['CSeq', 'From', 'To'],
        '3XX': ['CSeq', 'From', 'To'],
        '4XX': ['CSeq', 'From', 'To'],
        '5XX': ['CSeq', 'From', 'To'],
        '6XX': ['CSeq', 'From', 'To'],
        '7XX': ['CSeq', 'From', 'To'],
        '8XX': ['CSeq', 'From', 'To']
    }
    # TODO evaluate the used of a failing regex test to do this, it may be performance impact
    # TODO and a simple string bounds based check be better on performance.
    # TODO add logging to indicate whether both fail, this should be an issue with the message
    # Test to see if the message line is either a request or a response
    def parse_method_line(self, method_line):
        # first test for Response, we have generally receive more responses than requests
        try:
            result = vars(ResponseLine(method_line))
        except ValueError as detail:
            try:
                result = vars(RequestLine(method_line))
            except ValueError as detail:
                return None
        return result

    # Parse a SIP Header Line
    # value is the full header line as parsed from SIP message.
    # returns a dictionary with the header name and original raw value, along with a named "parsed"
    # object which contains the parsed values or a a single value of "header_value" if the header is unknown
    # see individual header classes for their result structure in the "parsed" object
    def parse_header(self, value):
        parsed = {}
        rematches = SIPParser.__header_syntax.match(value)
        if not rematches:
            raise ValueError('Invalid SIP Header(' + value + ')')

        self.header_name, self.header_value = rematches.groups()

        parsed['header_name'] = self.header_name
        parsed['header_raw'] = self.header_value

        try:
            parsed['parsed'] = vars(self.parser_dictionary[self.header_name](self.header_value))
        except ValueError as detail:
            print 'Error Parsing Header: ' + detail
            parsed['parsed'] = None
        except KeyError as detail:
            print 'Error Parsing Header: ' + str(detail)
            parsed['parsed'] = vars(UnknownHeader(self.header_value))

        return parsed

    def parse_message(self, sip_message):
        logger = logging.getLogger( 'sipLogger.sip_parse.SIPParser' )
        logger.info( 'Parsing SIP message' )
        message_dictionary = {}  # Storage location for our message dictionary
        # 0 = Pre Method Line
        # 1 = Got Method
        # 2 = Got Call-ID
        # 3 = In SDP
        message_state = 0
        parse_sdp = 0
        content_type = ""
        content_length = 0

        via_index = 0
        rr_index = 0

        lines = sip_message.splitlines()
        body_list = []
        header_processed_list = []

        # Basic top down parser, needs moved to class of it's own and dictionary of results.
        for line in lines:

            logger.info( 'Checking the message state' )
            if line == "" and message_state < 3 and content_length > 0:  # Next line starts body if we have any content length
                message_state = 3
                logger.info( 'Message state set to 3' )
                continue


            if line != "" and message_state >= 3:  # Handles Body
                # Currently we only handle SDP, will need to support Multi-part and SDP along with other bodies soon.
                if content_type == "application/sdp":  # We have SDP and can parse it
                    logger.info( 'Parsing SDP' )
                    sdp_line = line.split('=')
                    body_list.append(sdp_line)
                    logger.info( 'SDP appdended to body_list' )
                    logger.debug( 'body_list: {}'.format( body_list ) )
                logger.warn( 'Content type is not SDP other protocols are not supported at this time' )

            if line != "" and message_state == 0:
                logger.info( 'Parsing method line' )
                result = self.parse_method_line(line)
                if result is not None:
                    logger.info( 'Checking if REQUEST' )
                    try:
                        if result['type'] == "REQUEST":
                            logger.info( 'Adding REQUEST to message_dictionary' )
                            message_dictionary['type'] = result['type']
                            message_dictionary[result['type']] = result['method']
                            message_dictionary['r_uri'] = result['uri']
                            logger.debug( 'message_dictionary'.format( message_dictionary ) )
                        else:  # If not a request and we have result it has to be response.
                            logger.info( 'Message not a REQUEST updating message_dictionary' )
                            message_dictionary['type'] = result['type']
                            message_dictionary[result['type']] = result['code']
                            message_dictionary['response_text'] = result['text']
                            logger.debug( 'message_dictionary'.format( message_dictionary ) )
                    except KeyError as e:
                        logger.error( 'Key not supported: {}'.format( result['type'] ) )
                    logger.info( 'Message state set to 1' )
                    message_state = 1
                    continue

            if line != "" and 1 <= message_state <= 2:  # Process Header Lines
                logger.info( 'Parsing header line' )
                header_object = self.parse_header(line)

                # TODO Use a command pattern to process method?
                if header_object is not None:
                    header_processed_list.append(header_object['header_name'])  # Add our processed header to the list
                    logger.info( 'Header object name appended to header_processed_list' )
                    logger.debug( 'Header object name: {}'.format( header_object['header_name'] ) )
                    if 'parsed' in header_object.keys():  # Need to make sure we have something to look at
                        header_dictionary = header_object['parsed']
                        #print header_dictionary
                        # Begin tests and packing work.
                        # TODO Need to pack the Via and Record or other multi-headers with a sequence number
                        # TODO this sequence is used when processing the message as they are used in certain order
                        # Test for content-length and other needed items for processing
                        if 'content_length' in header_dictionary.keys():
                            content_length = header_dictionary['content_length']  # Need local copy to process message

                        if 'content_type' in header_dictionary.keys():
                            content_type = header_dictionary['content_type']  # Need local copy to process body

                        if 'Via' == header_object['header_name']:
                            if via_index == 0:  # First Via Header need to create list and put in via,
                            # top down incremental
                                message_dictionary[header_object['header_name']] = []
                            message_dictionary[header_object['header_name']].append(header_object['parsed'])
                            via_index += 1
                            continue

                        # Header needs stored if not overrode in above
                        message_dictionary[header_object['header_name']] = header_object['parsed']

                else:
                    logger.error( 'Failed to parse header: {}'.format( header_object ) )

        # Assign our body to our storage
        if content_length > 0:
            message_dictionary['body'] = {}
            message_dictionary['body'][content_type] = body_list

        # TODO Move Sanity checks to their own function
        # # TODO some RFC-3261 Sanity checks on message, like are all required headers present?
        try:
            if message_dictionary['type'] == "REQUEST":
                if all(value in header_processed_list for value in
                       self.request_required_dictionary[message_dictionary['REQUEST']]):
                    message_dictionary['sanity'] = True
                else:
                    message_dictionary['sanity'] = False
        except KeyError as e:
            logger.error( 'Key not Supported: {}'.format( e ) )

        # TODO finish responses sanity check, don't want to have to
        # TODO create item in dictionary for each message, need to do ranges
        # TODO Can do range by putting major number in key of dict and using math to create major from code,
        # TODO then look for it, e.g. major = int(code/100), required_header_list = response_dict[major]()
        # else:
        #     if all(value in header_processed_list for value in
        #            self.response_required_dictionary[message_dictionary['RESPONSE']]):
        #         print "good to go!"
        #     else:
        #         print "not good to go"
        #
        return message_dictionary

# Here we define quick tests to exercise the parsing classes
# Tests
if __name__ == '__main__':
    #  TODO Finish tests

    # Request and Response Tests:
    # Request Test(s)
    tmp_test_list = ['INVITE sip:joe@192.168.56.176 SIP/2.0',
                     'ACK sip:john@jacobs.edu SIP/2.0',
                     'CANCEL sip:dave@10.0.0.1 SIP/2.0',
                     'BYE sip:noone@invalid.tst SIP/2.0',
                     'INFO sip:tin@lizzy.invalid.tst SIP/2.0']
    for tmp_test_line in tmp_test_list:
        tmp_test = RequestLine(tmp_test_line)
        print 'Request Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print 'Request Failed--->' + tmp_test_line + '<---'

    # Fail on Response line in Request test
    try:
        tmp_test = RequestLine('SIP/2.0 100 Trying -- your call is proceeding')
        print 'You shouldn not see this:', vars(tmp_test)
    except ValueError as detail:
        print 'As expected handling exception:', detail

    # Response Test(s)
    tmp_test_list = ['SIP/2.0 100 Trying -- your call is proceeding',
                     'SIP/2.0 200 OK',
                     'SIP/2.0 484 Not Found']

    for tmp_test_line in tmp_test_list:
        #tmp_test_line = 'INVITE sip:joe@192.168.56.176 SIP/2.0'
        tmp_test = ResponseLine(tmp_test_line)
        print 'Response Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print 'Response Failed--->' + tmp_test_line + '<---'

    try:
        tmp_test = ResponseLine('INVITE sip:bob@192.168.56.176 SIP/2.0')
        print 'You shouldn not see this:', vars(tmp_test)
    except ValueError as detail:
        print 'As expected handling exception:', detail

    # Header Tests:
    # Record-Route, 20.30
    tmp_test_list = ['<sip:192.168.56.172:8080;transport=ws;r2=on;lr=on>']

    for tmp_test_line in tmp_test_list:
        tmp_test = RecordRoute(tmp_test_line)
        print 'Record_Route Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print 'Record_Route Failed--->' + tmp_test_line + '<---'


    # Via, 20.42
    tmp_test_list = ['SIP/2.0/UDP 192.168.56.172;branch=z9hG4bK743e.754a77de8a101e546ed5da9c75b990ff.0',
                     'SIP/2.0/WS lm3tqro83ime.invalid;rport=51803;received=192.168.56.1;branch=z9hG4bK2907341',
                     'SIP/2.0/UDP 192.168.56.172:5061;branch=z9hG4bK743e.754a77de8a101e546ed5da9c75b990ff.0',
                     'SIP/2.0/UDP 192.168.56.172:5061',  # Via needs to have a branch to be proper,
                     'SIP/2.0/TCP 192.168.56.172',  # but these test the parsing logic
                     'SIP/2.0/TCP 192.168.212.5:1031;branch=z9hG4bK99459324dca7564c6288fd59954c008c;rport']

    for tmp_test_line in tmp_test_list:
        tmp_test = Via(tmp_test_line)
        print 'Via Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print '****Via Failed--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'


    # Max-Forwards, 20.22
    tmp_test = MaxForwards('16')
    print 'Max-Forwards Test', vars(tmp_test)
    if tmp_test.max_forwards == 16 and str(tmp_test) == "16":
        print '    Success'
    else:
        print 'Max-Forwards Failed'

    # From, 20.20
    tmp_test_list = ['<sip:johnh@openrpr.org>;tag=i848d65132',
                     '\"John Holmes\" <sip:johnh@openrpr.org>;tag=i848d65132]',
                     '<sip:johnh@openrpr.org>',
                     'None <sip:from_heartbeat-observed-moducom-pfn_moducom-212004@192.168.212.5:1031>;tag=d35031c9d441f75089c62de1733c0142']

    for tmp_test_line in tmp_test_list:
        tmp_test = From(tmp_test_line)
        print 'From Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print '****From Failed--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'

    # To, 20.39
    tmp_test_list = ['<sip:joesmoe@192.168.56.176>;tag=i848d65132',
                     '\"Joe Smoe\" <sip:joesmoe@192.168.56.176>;tag=nd754ap92hng.O8954hioan.0]',
                     '<sip:joesmoe@192.168.56.176>',
                     '<sip:192.168.212.4>']  # From options as example.

    for tmp_test_line in tmp_test_list:
        tmp_test = To(tmp_test_line)
        print 'To Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print '****To Failed--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'

    # Contact, 20.10
    tmp_test_list = ['<sip:i70likmv@lm3tqro83ime.invalid;alias=192.168.56.1~51803~5;transport=ws;ob>;audio;video;text;data;+croc.sdkversion=\"<1>\"']

    for tmp_test_line in tmp_test_list:
        tmp_test = Contact(tmp_test_line)
        print 'Contact Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print '****Contact Failed--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'

    # Call-ID, 20.8
    tmp_test_list = ['tvkrrelrrg8i09eei7t7',
                     'f96b282e81d23f388d5bdfc50a583fa9@192.168.191.9']

    for tmp_test_line in tmp_test_list:
        tmp_test = CallID(tmp_test_line)
        print 'Call-ID Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print '****Call-ID Failed--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'

    # CSeq, 20.16
    tmp_test_list = ['3882 INVITE',
                     '274 OPTIONS']

    for tmp_test_line in tmp_test_list:
        tmp_test = CSeq(tmp_test_line)
        print 'CSeq Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print '****CSeq Failed--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'

    # Allow: 20.5
    tmp_test_list = ['INVITE, ACK, OPTIONS, CANCEL, BYE',
                     'ACK,CANCEL,BYE,OPTIONS,NOTIFY,INVITE,UPDATE,REFER',
                     'ACK, CANCEL,BYE ,OPTIONS, NOTIFY,INVITE,UPDATE,REFER',
                     'ACK, CANCEL, BYE, OPTIONS, NOTIFY, INVITE, UPDATE, REFER']

    for tmp_test_line in tmp_test_list:
        tmp_test = Allow(tmp_test_line)
        print 'Allow Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print '****Allow Failed(!!!This may be ok, normalization!!!)--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'

    # Call-Info, 20.9
    tmp_test_list = ['<http://wwww.example.com/alice/photo.jpg> ;purpose=icon,<http://www.example.com/alice/> ;purpose=info',
                     '<http://wwww.example.com/alice/photo.jpg> ;purpose=icon, <http://www.example.com/alice/> ;purpose=info']

    for tmp_test_line in tmp_test_list:
        tmp_test = CallInfo(tmp_test_line)
        print 'Call-Info Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print '****Call-Info Failed(!!!This may be ok, normalization!!!)--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'

    # Supported 20.37
    tmp_test_list = ['path,outbound,gruu,tdialog',
                     'path, outbound, gruu, tdialog',
                     '100rel',
                     'path, 100rel']

    for tmp_test_line in tmp_test_list:
        tmp_test = Supported(tmp_test_line)
        print 'Supported Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print '****Supported Failed(!!!This may be ok, normalization!!!)--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'

    # User-Agent:
    tmp_test_list = ['Crocodile SDK v<%= pkg.version %>; JsSIP 0.3.0-crocodile-1-devel; Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.124 Safari/537.36',
                     'Softphone Beta1.5',
                     'fake.org-Telecom-%i-bcf-0.0.15']

    for tmp_test_line in tmp_test_list:
        tmp_test = UserAgent(tmp_test_line)
        print 'User-Agent Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print '****User-Agent Failed(!!!This may be ok, normalization!!!)--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'

    # Content-Type, 20.15
    tmp_test_list = ['application/sdp', 'text/html; charset=ISO-8859-4']

    for tmp_test_line in tmp_test_list:
        tmp_test = ContentType(tmp_test_line)
        print 'Content-Type Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print '****Content-Type Failed--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'

    # Content-Length, 20.14
    tmp_test_list = ['0', '310', '512', '173']

    for tmp_test_line in tmp_test_list:
        tmp_test = ContentLength(tmp_test_line)
        print 'Content-Length Test:', vars(tmp_test)
        if tmp_test_line == str(tmp_test):
            print '    Success Comparing--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'
        else:
            print '****Content-Length Failed--->' + tmp_test_line + '<--- to --->' + str(tmp_test) + '<---'


    # TODO Priority
    # TODO Require
    # TODO Route
    # TODO Server
    # TODO Subject
    # TODO Unsupported

    sip_parser = SIPParser()
    print sip_parser.parse_header('Via: SIP/2.0/UDP 192.168.212.5:1031;branch=z9hG4bK18844c13f61433b8754abb950ad904f4;rport')
    print sip_parser.parse_header('Max-Forwards: 70')
    print sip_parser.parse_header('From: 2605551000 <sip:2605551000@192.168.212.5:1031>;tag=368a1f088f6545e662d5c791ac6588af')
    print sip_parser.parse_header('To: <sip:911@192.168.212.4>')
    print sip_parser.parse_header('Call-ID: 44dcc316bdedbaac')
    print sip_parser.parse_header('CSeq: 200 INVITE')
    print sip_parser.parse_header('Contact: Anonymous <sip:2605551000@192.168.212.5:1031>;+sip.instance="<urn:uuid:00000000-0000-1000-8000-00085D13F069>"')
    print sip_parser.parse_header('Expires: 300')
    print sip_parser.parse_header('User-Agent: fake.org-Telecom-%i-bcf-0.0.15')
    print sip_parser.parse_header('cisco-GUID: 1816104342-279044231-4235615245-2414420439')
    print sip_parser.parse_header('h323-conf-id: 1816104342-279044231-4235615245-2414420439')
    print sip_parser.parse_header('Content-Length: 266')
    print sip_parser.parse_header('Content-Type: application/sdp')


    test_sip_message_list = []

    sip_message_request = """INVITE sip:911@192.168.212.4:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.212.5:1031;branch=z9hG4bK18844c13f61433b8754abb950ad904f4;rport
Max-Forwards: 70
From: 2605551000 <sip:2605551000@192.168.212.5:1031>;tag=368a1f088f6545e662d5c791ac6588af
To: <sip:911@192.168.212.4>
Call-ID: 44dcc316bdedbaac
CSeq: 200 INVITE
Contact: Anonymous <sip:2605551000@192.168.212.5:1031>;+sip.instance="<urn:uuid:00000000-0000-1000-8000-00085D13F069>"
Expires: 300
User-Agent: fake.org-Telecom-%i-bcf-0.0.15
cisco-GUID: 1816104342-279044231-4235615245-2414420439
h323-conf-id: 1816104342-279044231-4235615245-2414420439
Content-Length: 266
Content-Type: application/sdp

v=0
o=MxSIP 0 1 IN IP4 192.168.191.190
s=SIP Call
c=IN IP4 192.168.212.5
t=0 0
m=audio 3000 RTP/AVP 0 110 101
a=rtpmap:0 PCMU/8000
a=rtpmap:110 PCMU/16000
a=rtpmap:101 telephone-event/8000
a=silenceSupp:off - - - -
a=fmtp:101 0-15
a=ptime:20
a=sendrecv
"""
    test_sip_message_list.append(sip_message_request)

    sip_message_response = """SIP/2.0 100 TRYING
Via: SIP/2.0/UDP 192.168.212.5:1031;branch=z9hG4bK18844c13f61433b8754abb950ad904f4;rport
To: <sip:911@192.168.212.4>;tag=bac145859d87469aad181296966d1b36
From: "2605551000 " <sip:2605551000@192.168.212.5:1031>;tag=368a1f088f6545e662d5c791ac6588af
Call-ID: 44dcc316bdedbaac
CSeq: 200 INVITE
Contact: <sip:911@192.168.212.4:5060>
Content-Length: 0
"""

    test_sip_message_list.append(sip_message_response)

    sip_message_response = """SIP/2.0 183 Session Progress
Via: SIP/2.0/UDP 192.168.212.5:1031;branch=z9hG4bK18844c13f61433b8754abb950ad904f4;rport
To: <sip:911@192.168.212.4>;tag=bac145859d87469aad181296966d1b36
From: "2605551000 " <sip:2605551000@192.168.212.5:1031>;tag=368a1f088f6545e662d5c791ac6588af
Call-ID: 44dcc316bdedbaac
CSeq: 200 INVITE
Contact: <sip:911@192.168.212.4:5060>
Content-Type: application/sdp
Content-Length: 193

v=0
o=- 0 1 IN IP4 192.168.212.6
s=Moducom_0
c=IN IP4 192.168.212.6
t=0 0
m=audio 5070 RTP/AVP 0 101
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendrecv
"""

    test_sip_message_list.append(sip_message_response)

    sip_message_request = """OPTIONS sip:192.168.212.4:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.212.5:1031;branch=z9hG4bKcc1b742dd616323735928c87bfcba5c6;rport
Max-Forwards: 70
From: None <sip:from_heartbeat-observed-moducom-pfn_moducom-212004@192.168.212.5:1031>;tag=53a00292d49e7997ca3b0fb33da7e4c3
To: <sip:192.168.212.4>
Call-ID: d3d3496d9cfac6d03a3d484aa3929853@192.168.191.9
CSeq: 305 OPTIONS
Contact: Anonymous <sip:from_heartbeat-observed-moducom-pfn_moducom-212004@192.168.212.5:1031>
User-Agent: fake.org-Telecom-%i-bcf-0.0.15
Content-Length: 0
"""

    test_sip_message_list.append(sip_message_request)

    sip_message_request = """INVITE sip:bob@192.168.56.176 SIP/2.0
Record-Route: <sip:192.168.56.172;r2=on;lr=on>
Record-Route: <sip:192.168.56.172:8080;transport=ws;r2=on;lr=on>
Via: SIP/2.0/UDP 192.168.56.172;branch=z9hG4bK2555.340b7fbd7a87eba792ef61dfd69d4191.0
Via: SIP/2.0/WS q8853dn47ugu.invalid;rport=57625;received=192.168.56.1;branch=z9hG4bK4525730
Max-Forwards: 16
To: <sip:bob@192.168.56.176>
From: <sip:example@example.org>;tag=jht2pgcj5k
Call-ID: fj0un9alfh3btkt09a4f
CSeq: 3609 INVITE
Allow: ACK,CANCEL,BYE,OPTIONS,NOTIFY,INVITE,UPDATE,REFER
Supported: path,outbound,gruu,tdialog
Contact: <sip:matddmbm@q8853dn47ugu.invalid;alias=192.168.56.1~57625~5;transport=ws;ob>;audio;video;text;data;+croc.sdkversion="<1>"
Content-Type: application/sdp
User-Agent: Crocodile SDK v<%= pkg.version %>; JsSIP 0.3.0-crocodile-1-devel; Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.124 Safari/537.36
Content-Length: 310

v=0
o=bob 3647604938 3647604938 IN IP4 192.168.56.172
s=
c=IN IP4 192.168.56.172
t=0 0
m=message 2855 TCP/MSRP *
a=accept-types:text/plain
a=path:msrp://192.168.56.172:9000/581f653-7ff-12;tcp msrp://flye3x3q.invalid:2855/lah55ri27l;ws
a=oldmediaip:flye3x3q.invalid
a=oldmediaip:flye3x3q.invalid
"""

    test_sip_message_list.append(sip_message_request)

    for sip_message in test_sip_message_list:
        result = sip_parser.parse_message(sip_message)
        print "-------------->New Result:%s,%s,%s<--------------" % (result['Call-ID']['call_id'], result['type'],
                                                                     result[result['type']])
        print result

    # Cheap attributes test, it worked at least
    param_object = URIParameters('branch=189328ad7b43p8923nfud8nig;test=tester')
    print vars(param_object)

    exit()
