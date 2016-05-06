import logging
import string, sys, re

from pprint import pformat
from zope.interface import implements
from xml.sax.saxutils import escape
from xml.sax.saxutils import unescape

from xml.dom.minidom import parseString


from twisted.internet import reactor
from twisted.internet.protocol import DatagramProtocol
from twisted.internet.protocol import Protocol

from twisted.web.client import Agent
from twisted.internet.defer import Deferred

from NeoSBC.rest import *
from NeoSBC.storage.callstore import *
from NeoSBC.stateMachine.sipstatemachine import SIPStateMachine
from NeoSBC.parsers.sip_parse import *
from NeoSBC.stateMachine.statemachine import StateMachine

__author__ = 'jkinney'


pending_call_id = ""
logger = logging.getLogger( 'sipLogger.sip_UA' )

# TODO 1. Need to support MIME Multi-part Bodies for SIP


class SIP_UA(DatagramProtocol):

    REST_agent = Agent(reactor)

    def __init__(self, security_rule_list, seczone=None):
        self.sipstatemachine = SIPStateMachine()
        self.seczone = seczone or 'unk'
        self.security_rule_list = security_rule_list

        self.sip_parser = SIPParser()
        logger.info( 'SIP User Agent instatiated' )

# Change to use sip_constructor

    def prepare_forwarded_invite(self, call_record):
        logger.info( 'Preparing forwading invite' )
        outgoing_message = { 'method': 'INVITE'}

        # TODO Need to fix below from routing info that should be available to the forward method after the call is routed
        outgoing_message['sip_r_uri'] = 'sip:bob@notright.xxx'

        outgoing_message['sip_to'] = call_record['sip_to']  # TODO Update To
        outgoing_message['sip_from'] = call_record['sip_from']  # TODO Update From
        outgoing_message['sip_call_id'] = call_record['sip_call_id']
        # TODO Create new Cseq
        outgoing_message['sip_allow'] = call_record['sip_allow']
        outgoing_message['sip_supported'] = call_record['sip_supported']
        # TODO Create Contact from local information
        outgoing_message['sip_contact'] = call_record['sip_contact']
        outgoing_message['sip_user_agent'] = 'fake.org telecom SBC'

        # TODO Need to manipulate SDP for proxies as needed, for now we are just using SDP as is from original INVITE
        # TODO Both Content Type and Content-Length need taken from actual original after SDP has been update for proxy
        outgoing_message['sip_content_type'] = 'application/sdp'
        outgoing_message['sip_content_length'] = '0'

        logger.info( 'Forwarding invite contents: {}'.format( outgoing_message ) )

        return outgoing_message

    def forward(self, rcvd_message):
        # Retrieve our SIP CAll ID
        sip_call_id = rcvd_message['Call-ID']['call_id']
        logger.info( 'Forwarding call from call id: {}'.format( sip_call_id ) )

        forward_result = {'status': 'failed'}

        # TODO Need to get routing result information to formulate forwarded INVITE.


        logger.info( 'Seeing if call exists' )
        call_record = CallStore().find_call(sip_call_id)
        if call_record is not None and rcvd_message[rcvd_message['type']] == '100':
            logger.info( 'Call exists forward call_record(routing_result)'.format( call_record['routing_result'] ) )


        outgoing_message = self.prepare_forwarded_invite(call_record)
        self.send_sip_message(outgoing_message)
        logger.info( 'Call fowarding result: {}'.format( forward_result ) )


        # TODO find SIP UA and interface to send out our new INVITE
        return forward_result

    def route_call(self, rcvd_message):
        # Retrieve our SIP CAll ID
        sip_call_id = rcvd_message['Call-ID']['call_id']
        logger.info( 'Routing call from call id: {}'.format( sip_call_id ) )

        # Set up our state, presume deny all
        routing_result = {'status': 'failed'}

        # Need to make sure we have a call and we can only route on an INVITE, preferably creating a new dialog
        logger.info( 'Seeing if call exists' )
        call_record = CallStore().find_call(sip_call_id)
        if call_record is not None and rcvd_message[rcvd_message['type']] == 'INVITE':
            logger.info( 'Routing call' )

            for rule in self.security_rule_list:
                logger.info( 'Evaluating rule: {}'.format( rule['rule_name'] ) )

                #First make sure this rule even applies to this seczone, if not then it doesn't apply
                logger.info( 'Checking if rule applies to security zone: {}'.format( self.seczone ) )
                if self.seczone == rule['from_seczone']:

                    logger.info( 'Checking destination' )
                    for destination in rule['destination_list']:
                        logger.info( 'Evaluating destination: '.format( destination ) )
                        logger.info( 'Evaluating destination(rcvd_message): {}'.format( rcvd_message['r_uri'] ) )

                        pattern = re.compile(destination)
                        match_list = re.findall(pattern, rcvd_message['r_uri'])

                        logger.info( 'Checking if there is a match' )
                        if len(match_list) >= 1:  # We have a match
                            logger.info( 'Updating routing status' )
                            routing_result['status'] = rule['rule_type']

                            logger.info( 'Checking if we need to evaluate the outgoing R-URI' )
                            if rule['rule_type'] == "permit":  # We must now evaluate the outgoing R-URI and send-to params
                                match_index = 1
                                logger.info( 'Routing to: {} zone'.format( rule['to_seczone'] ) )
                                routing_result['to_seczone'] = rule['to_seczone']
                                # TODO need to handle "using" clause in syntax for "send-to" parameters to of outgoing UDP socket
                                # TODO look at model of going through the uri_pattern and then match to matches, this is opposite logic
                                for match in match_list[0]:
                                    logger.info( 'Going through the matches' )
                                    # TODO fix this!!!! it is not right, just a simple skip of empty matches, needs some type of recursion over replaced string maybe
                                    if match is not "":
                                        new_rule = rule['uri_pattern']
                                        current_token = "%" + str(match_index)
                                        routing_result['outgoing_uri'] = new_rule.replace(current_token, match)

                            # TODO need to have some other failed result that didn't route and one that was denied, then no 100trying, terminate SIP session on deny and failure message on fail

            # Need to store the response into the call record
            # TODO move this operation into the call_store class.

            # TODO return a routing_failed if something is wrong with above, there could be incomplete rule, or failure to find call, etc...

        # TODO fix up to using CallStore class now, this is unsafe way to use the CallStore, couple reasons
        if routing_result['status'] is not 'failed':
            logger.info( 'Updating result' )
            call_record['routing_result'] = routing_result

        logger.info( 'Routing result: {}'.format( routing_result ) )

        return routing_result


    # Early version of SIP message engine, this will get more powerful as more methods are added and needed
    def send_sip_message(self, outgoing_message, remote_host=None, remote_port=None):

        # TODO Do we need to see if host is support like IP is below. We will store
        # the host, but need to test when it is actual host/domain that it works.
        # TODO see if we can share the dictionary from sip_parser.py for here
        header_list = ['From', 'To', 'Call-ID', 'CSeq', 'User-Agent', 'Via', 'Content-Type', 'Content-Length']

        message_keys = outgoing_message.keys()  # Used to quickly determine if a header needs created

        # Check to see if this is request or response
        logger.info( 'Checking message type' )
        if outgoing_message['type'] == 'REQUEST':
            logger.info( 'Message is REQUEST' )
            request_line = RequestLine()
            request_line.method = outgoing_message['REQUEST']
            request_line.uri = outgoing_message['r_uri']
            raw_pdu = str(request_line) + "\r\n"
        else:
            logger.info( 'Message is RESPONSE' )
            response_line = ResponseLine()
            response_line.code = outgoing_message['RESPONSE']
            response_line.text = outgoing_message['response_text']
            raw_pdu = str(response_line) + "\r\n"

        logger.info( 'Checking headers' )

        for header in header_list:
            if header in message_keys:
                if header == "Via":  # Override Via as it is stored as a list
                    # Now put the highest Via IP and port into remote_host and remote_port
                    logger.info( 'Putting Via IP and port into remote_host and remote_port' )
                    if remote_host is None:
                        remote_host = outgoing_message[header][0]['host']
                    if remote_port is None:
                        if outgoing_message[header][0]['port'] is not None:
                            remote_port = outgoing_message[header][0]['port']
                        else:
                            remote_port = 5060
                    # Now Need to unpack the list and place strings into sip message
                    logger.info( 'Making sip message' )
                    for via_object in outgoing_message[header]:
                        tmp_object = self.sip_parser.parser_dictionary[header]()
                        tmp_object.from_dict(via_object)
                        raw_pdu += "%s: %s\r\n" % (header, str(tmp_object))
                    continue
                    # TODO RecordRoute Header like Via

                tmp_object = self.sip_parser.parser_dictionary[header]()
                tmp_object.from_dict(outgoing_message[header])
                raw_pdu += "%s: %s\r\n" % (header, str(tmp_object))
        # TODO Move Prints to Log Events
        logger.info( 'Writing SIP Message to {}:{}'.format( remote_host, remote_port ) )
        logger.debug( 'raw_pdu: {}'.format( raw_pdu ) )
        self.transport.write(raw_pdu, (remote_host, remote_port))
        logger.info( 'SIP Message sent' )

    def send_100Try(self, rcvd_message):

        logger.info( 'Sending 100 Try Message' )
        malformed = 1
        # Should we just defacto copy message? I think based on fsm and message in reaction to this pulls from call_store
        outgoing_message = rcvd_message

        # TODO Need to handle other Methods, and possibly combine many of them
        # Need to determine what we are 100 Trying back to,
        # doesn't matter too much, but only pertains to certain situations
        logger.info( 'Checking if message is INVITE' )
        if rcvd_message[rcvd_message['type']] == "INVITE":
            logger.info( 'Message is INVITE, making RESPONSE message' )
            # Only changing lines that need changed, or deleting ones that would consume the message engine
            #outgoing_message["prot_ver"] = "SIP/2.0"
            outgoing_message['type'] = 'RESPONSE'
            outgoing_message['RESPONSE'] = '100'
            outgoing_message['response_text'] = 'Trying -- your call is proceeding'
            del outgoing_message['Content-Type']  # 100 Trying doesn't generally have any body content
            outgoing_message['Content-Length']['content_length'] = 0
            malformed = 0


        logger.info( 'Checking if the message is malformed' )
        if not malformed:
            self.send_sip_message(outgoing_message)
            logger.info( 'Message sent' )
        else:
            logger.error( 'Message malformed' )

    def send_180Ring(self, rcvd_message):
        malformed = 1
        outgoing_message = rcvd_message # For now we are using a reference, this may not be a good way to do it, other than the dialogic evolves with each message

        # Need to determine what are are 100 Trying back to, doesn't matter too much, but only pertains to certain situations
        if rcvd_message[rcvd_message['type']] == '100':
            # Only changing lines that need changed, or deleting ones that would consume the message engine
            #outgoing_message["prot_ver"] = "SIP/2.0"
            outgoing_message['type'] = 'RESPONSE'
            outgoing_message["RESPONSE"] = "180"
            logger.info( 'The call is ringing' )
            outgoing_message["response_text"] = "Ringing -- your call is ringing"
            malformed = 0

        logger.info( 'Checking if the message is malformed' )
        if not malformed:
            self.send_sip_message(outgoing_message)
            logger.info( 'Message sent' )
        else:
            logger.error( 'Message malformed' )

    def send_200OK_wSDP(self, sip_call_id, sdp):
        malformed = 1

        logger.info( 'Checking if call exists' )
        outgoing_message = CallStore().find_call(sip_call_id)
        if outgoing_message is not None:
            logger.info( 'Call is ok, making RESPONSE message' )
            #outgoing_message["prot_ver"] = "SIP/2.0"
            outgoing_message['type'] = 'RESPONSE'
            outgoing_message['RESPONSE'] = '200'
            outgoing_message["response_text"] = "OK"
            outgoing_message["200_OK_SDP"] = sdp  # TODO Fix!!!!
            malformed = 0

        logger.info( 'Checking if the message is malformed' )
        if not malformed:
            self.send_sip_message(outgoing_message)
            logger.info( 'Message sent' )
        else:
            logger.error( 'Message malformed' )

    def send_200OK(self, rcvd_message):
        malformed = 1

        sip_call_id = rcvd_message['Call-ID']['call_id']
        outgoing_message = rcvd_message # For now we are using a reference, this may not be a good way to do it, other than the dialogic evolves with each message

        # Need to determine what are are 100 Trying back to, doesn't matter too much, but only pertains to certain situations
        logger.info( 'Checking if call is 180' )
        if rcvd_message[rcvd_message['type']] == '180': # We are answering a Ringing Call
            # Only changing lines that need changed, or deleting ones that would consume the message engine
            #outgoing_message["prot_ver"] = "SIP/2.0"
            logger.info( 'Making RESPONSE message' )
            outgoing_message['type'] = 'RESPONSE'
            outgoing_message["RESPONSE"] = '200'
            outgoing_message["response_text"] = "OK -- your call is answered"
            malformed = 0

        logger.info( 'Checking if the message is malformed' )
        if not malformed:
            self.send_sip_message(outgoing_message)
            logger.info( 'Message sent' )
        else:
            logger.error( 'Message malformed' )

    def cancel_call(self, rcvd_message):
        malformed = 1

        sip_call_id = rcvd_message['Call-ID']['call_id']
        outgoing_message = rcvd_message # For now we are using a reference, this may not be a good way to do it, other than the dialogic evolves with each message

        logger.info( 'Checking if call exists' )
        if CallStore().call_exists(sip_call_id):
            logger.info( 'Call exists making cancel RESPONSE message' )
            #outgoing_message["prot_ver"] = "SIP/2.0"
            outgoing_message['type'] = 'RESPONSE'
            outgoing_message["RESPONSE"] = '200'
            outgoing_message["response_text"] = "Cancelling"
            malformed = 0
            # TODO Delete record from call_store
            # TODO Remove call_id from list


        logger.info( 'Checking if the message is malformed' )
        if not malformed:
            self.send_sip_message(outgoing_message)
            logger.info( 'Message sent' )
        else:
            logger.error( 'Message malformed sip_is: {}'.format( sip_call_id ) )

    def disconnecting_call(self, rcvd_message):
        malformed = 1

        sip_call_id = rcvd_message['Call-ID']['call_id']
        outgoing_message = rcvd_message # For now we are using a reference, this may not be a good way to do it, other than the dialogic evolves with each message

        logger.info( 'Cheking if the call exists' )
        if CallStore().call_exists(sip_call_id):
            #outgoing_message["prot_ver"] = "SIP/2.0"
            logger.info( 'Call exists making disconnecting_call RESPONSE' )
            outgoing_message['type'] = 'RESPONSE'
            outgoing_message["RESPONSE"] = '200'
            outgoing_message["response_text"] = "OK"
            malformed = 0

        logger.info( 'Checking if the message is malformed' )
        if not malformed:
            self.send_sip_message(outgoing_message)
            logger.info( 'Message sent' )
        else:
            logger.error( 'Message malformed sip_is: {}'.format( sip_call_id ) )

    def acknowleged_call(self, rcvd_message):
        malformed = 1

        sip_call_id = rcvd_message['Call-ID']['call_id']
        outgoing_message = rcvd_message # For now we are using a reference, this may not be a good way to do it, other than the dialogic evolves with each message

        logger.info( 'Checking if call exists' )
        if CallStore().call_exists(sip_call_id):
            # TODO Update record in call_store
            logger.info( 'Call exists acknowleging the call: {}'.format( rcvd_message['sip_call_id'] ) )

    def cbResponse(self, response, pending_call_id):
        logger.debug( 'For SIP call id: {}'.format( pending_call_id ) )
        logger.debug( 'REST Response version: {}'.format( response.version ) )
        logger.debug( 'REST Response code: {}'.format( response.code ) )
        logger.debug( 'REST Response phrase: {}'.format( response.pharse ) )
        logger.debug( 'REST Response headers: {}'.format( pformat( list( response.header.getAllRawHeaders() ) ) ) )

        logger.info( 'Checking response code' )
        if response.code == 204:
            d = defer.succeed('')
            logger.info( 'Response defer succeeded' )
        else:
            class SimpleReceiver(Protocol):
                def __init__(s, d):
                    s.buf = ''; s.d = d
                def dataReceived(s, data):
                    s.buf += data
                def connectionLost(s, reason):
                    logger.warn( 'Connection lost: checking reason' )
                    print("Connection Lost")
                    # TODO: test if reason is twisted.web.client.ResponseDone, if not, do an errback
                    s.d.callback(s.buf)

            d = Deferred()
            if response.code == 201: # Created, for now we assume this means that we add a 3PCC SDP leg
                d.addCallback(self.handleRESTResponse, pending_call_id)

            response.deliverBody(SimpleReceiver(d))
            logger.info( 'Delivering body' )
        return d

    def handleRESTResponse(self, data, pending_call_id):
        #TODO, meke more robust and error proof, this is simple version
        logger.info( 'Received a valid REST response from media server for call: {}'.format( pending_call_id ) )
        logger.debug( 'XML Body: {}'.format( data ) )
        dom = parseString(data)
        call_response = dom.getElementsByTagName("call_response")
        #print(call_response[0].attributes["sdp"].value)
        logger.info( 'Sending 200OK_wSDP' )
        self.send_200OK_wSDP(pending_call_id, unescape(call_response[0].attributes["sdp"].value))
        logger.info( '200OK_wSDP send sucessfully' )

    def cbError(self, failure):
        failure.printTraceback()
        logger.error( '{}:{}'.format( type( failure.value ), failure ) )

    def cbShutdown(self, err):
        logger.info( 'Shutdown called' )

    def get_SDP(self, rcvd_message):
        #global call_store
        sip_call_id = rcvd_message['Call-ID']['call_id']

        # Need to get some SDP to use
        # TODO error checking and more error checking, this is quick blurt out on how to do this
        logger.info( 'Checking if call exists' )
        call_record = CallStore().find_call(sip_call_id)
        if call_record is not None:
            logger.info( 'Call exists making SDP' )
            SDPText = ""
            SDPList = call_record["INVITE_SDP"]
            for SDPTuple in SDPList:
                SDPText += escape("=".join(SDPTuple)) + "&#13;&#10;"

            # Need to detect media types, like audio, audio/video and message. Currently we hardcoded this, it needs detected from media.
            RESTBody = "<web_service version=\"1.0\"><call media=\"message\" signaling=\"no\" sdp=\"%s\" dtmf_mode=\"rfc2833\" async_dtmf=\"no\" async_tone=\"no\"/></web_service>" % (SDPText)
            raw_body = StringProducer(RESTBody)

            # Remove eventually, just to see the producer's output
            logger.debug( 'raw_body: {}'.raw_body.body )
            logger.debug( 'length: {}'.format( raw_body.length ) )

            # TODO Need to move to calls of def at least, need to configurize the URL and eventually have a failure detection and use of more than one XMS in pool
            REST_request = self.REST_agent.request("POST","http://192.168.56.138:81/default/calls?appid=app", None, raw_body)
            REST_request.addCallback(self.cbResponse, rcvd_message['Call-ID']['call_id'])
            ##REST_request.addCallback(self.dumpResponse)
            #REST_request.addBoth(self.cbShutdown)

    def HandleState(self, incoming_message):

        try:
            sip_call_id = incoming_message['Call-ID']['call_id']
        except KeyError as e:
            logger.error( 'Key not supported: {} exiting HandleState'.format( e ) )
            return

        logger.info( 'Checking if the call exists' )
        if CallStore().call_exists(sip_call_id):
            logger.info( 'Call exists getting the call state' )
            call_record = CallStore().find_call(sip_call_id)

            #Copy our incoming message to manipulate
            new_message = incoming_message
            # TODO put this method into CallStore as a way to provide the seczone and call_id to get back the new start state
            logger.info( 'Checking state' )
            if 'awaiting_state' in call_record:
                # Need to set start state
                logger.info( 'Setting the start state to: {}'.format( call_record['awaiting_state'] ) )
                self.sipstatemachine.callstate_fsm.set_start(call_record['awaiting_state'])
            else:
                # New Call or non-final message
                logger.info( 'Setting the start state to: idle' )
                self.sipstatemachine.callstate_fsm.set_start("Idle")

            logger.info( 'Running callstate fsm' )
            self.sipstatemachine.callstate_fsm.run(new_message[new_message['type']], self, new_message)
            # Done manipulating State now push back
            logger.info( 'Updating the call' )
            CallStore().update_call(sip_call_id, new_message)
        else:
            # TODO Need to send Error or lookup the call info from multi-cast bus
            logger.error( 'No dialog found for sip call id: {}'.format( sip_call_id ) )

    # Try to create a new call
    def create_call(self, direction, seczone, call_fragment):

        # Lets make some local variables to help with work
        logger.info( 'Creating call' )
        call_id = call_fragment['Call-ID']['call_id']
        branch_id = None

        # Check to see if there is a Via header and get the correct branch if there is
        logger.info( 'Checking if there is a Via header' )
        if 'Via' in call_fragment.keys():
            # Extract branch
            logger.info( 'Via header found making branch' )
            branch_object = vars(URIParameters(call_fragment['Via'][0]['attributes']))
            branch_id = branch_object['param']['branch']
            call_record = {'current_state': 'INITIAL',
                           'call_id': call_id,
                           'branch_id': branch_id,
                           'seczone': seczone,
                           'fragments': []}
        else:
            logger.info( 'No Via header found' )
            call_record = {'current_state': 'INITIAL',
                           'call_id': call_id,
                           'seczone': seczone,
                           'fragments': []}

        # Create our call_record_key from call_id and branch_id if it exists
        logger.info( 'Making call record' )
        call_record_key = call_id + "_" + branch_id if branch_id else call_id

        logger.info( 'Assigning the call' )
        if CallStore().assign_call(direction, call_record_key, call_record) is not None:
            logger.info( 'Adding the call fragment' )
            CallStore().add_call_fragment(direction, call_record_key, call_fragment)
            return True
        else:
            logger.error( 'Could not assign the call' )
            return False

    def datagramReceived(self, data, (host, port)):

        logger.info( 'rcvd SIP pdu from: {}:{} on {}'.format( host, port, self.seczone ) )
        logger.debug( 'Data recieved: {}'.format( data ) )

        # Parse our incoming SIP Message
        parsed_message = self.sip_parser.parse_message(data)
        logger.info( 'Parsed message' )

        # Either first time for this call or re-invite
        logger.info( 'Checking if this is the first time for the call' )
        try:
            if parsed_message['type'] == 'REQUEST' and parsed_message[parsed_message['type']] == 'INVITE':
                if self.create_call('ingress', self.seczone, parsed_message) is True:
                    logger.info( 'Created new call' )
                    #self.HandleState(parsed_message)
                else:
                    logger.info( 'Must re-INVITE' )
            elif parsed_message['type'] == 'REQUEST':
                logger.info( 'InDialog Request' )
                #self.HandleState(parsed_message)
                # I would expect to find the call since this is indialog request per se
            elif parsed_message['type'] == 'RESPONSE':
                #self.HandleState(parsed_message)
                logger.info( 'Response' )
            else:
                logger.error( 'Something went wrong' )
        except KeyError as e:
            logger.error( 'Key not supported: {}'.format( e ) )



        # Legacy need to remove after above is working
        logger.info( 'Checking if the call exists' )
        try:
            if CallStore().call_exists(parsed_message['Call-ID']['call_id']) is not True:
                logger.info( 'Call does not exist adding to call list, first INVITE' )
                # TODO, sync state_machine with INVITE state, initiating, should only have new call in initial state
                CallStore().add_call(parsed_message['Call-ID']['call_id'], parsed_message)
        except KeyError as e:
            logger.error( 'Key not Supported: {}'.format( e ) )

        # Need to pass the start state, it could be determined by something like re-INVITE detection
        logger.info( 'Handling the call state' )
        self.HandleState(parsed_message)  # Elevate State based on method
