import logging
from NeoSBC.stateMachine.statemachine import StateMachine
from NeoSBC.storage.callstore import *

__author__ = 'jkinney'


class SIPStateMachine():

    def __init__(self):
        self.callstate_fsm = StateMachine()
        self.callstate_fsm.add_state("Idle", self.idle_fsm)
        self.callstate_fsm.add_state("Routing", self.routing_fsm)
        self.callstate_fsm.add_state("Blackhole", self.blackhole_fsm)
        self.callstate_fsm.add_state("Forwarding", self.forwarding_fsm)
        self.callstate_fsm.add_state("Forwarded", self.forwarded_fsm, end_state=1)
        self.callstate_fsm.add_state("Proceeding", self.proceeding_fsm)
        self.callstate_fsm.add_state("Ring", self.ring_fsm)
        self.callstate_fsm.add_state("Answering", self.answering_fsm)
        self.callstate_fsm.add_state("Answer", self.answer_fsm)
        self.callstate_fsm.add_state("InDialog", self.indialog_fsm, end_state=1)
        self.callstate_fsm.add_state("WaitACK", self.waiting_ack)
        self.callstate_fsm.add_state("WaitSDP", self.waiting_sdp, end_state=1)
        self.callstate_fsm.add_state("Cancelling", self.cancel_fsm)
        self.callstate_fsm.add_state("Cancelled", self.cancelled_fsm)
        self.callstate_fsm.add_state("Acknowleged", self.acknowleged_fsm)
        self.callstate_fsm.add_state("Disconnecting", self.disconnecting_fsm)
        self.callstate_fsm.add_state("Disconnected", self.disconnected_fsm)
        self.callstate_fsm.add_state("BYEWait4ACK", self.byewaitack_fsm)
        self.callstate_fsm.add_state("Delete", self.delete_fsm)
        self.callstate_fsm.add_state("Deleted", self.deleted_fsm, end_state=1)
        # We start FSM at Idle State
        self.callstate_fsm.set_start("Idle")

    def idle_fsm(self, method, sip_ua, rcvd_message):
        print "Start State:%s" % rcvd_message['Call-ID']['call_id']
        if method == "INVITE": # Need to send 100 Trying to accept
            # TODO Need to now route the call
            return ("Routing", method)
        elif method == "CANCEL":
            return "Cancelling", method
        elif method == "BYE":
            return "Disconnecting",  method
        elif method == "ACK":
            return "Acknowleged",  method
        elif method == "SUBSCRIBE":
            return "Subscribing", method
        elif method == "NOTIFY":
            return "Notified", method

    def byewaitack_fsm(self, method, sip_ua, rcvd_message):
        if method == "BYE":  # Need to set our awaiting_state to this state
            rcvd_message['awaiting_state'] = "BYEWait4ACK"
        elif method == "ACK":
            return "Delete", method

    def routing_fsm(self, method, sip_ua, rcvd_message):
        print "--->routing_fsm<---"
        if method == "INVITE":
            routing_result = sip_ua.route_call(rcvd_message)
            if routing_result['status'] == "permit":
                return "Proceeding", method
            else:  # This is anything other than permit, so we should blackhole the request for now
                return "Blackhole", method

    def blackhole_fsm(self, method, sip_ua, rcvd_message):
        print "Log Info:--->blackhole_fsm<--- sip_call_id:%s" % (rcvd_message['Call-ID']['call_id'])
        # TODO in future need to count the mishaps and eventually block the IP, or combination of IP and PORT in FW
        return "Delete", method

    def forwarding_fsm(self, method, sip_ua, rcvd_message):
        print "Log Info:--->forwarding_fsm<--- sip_call_id:%s" % (rcvd_message['Call-ID']['call_id'])
        sip_ua.forward(rcvd_message)
        # TODO Forward the INVITE after manipulation using the to_seczone's interface
        return "Forwarded", method

    def forwarded_fsm(self, method, sip_ua, rcvd_message):
        print "Log Info:--->forwarded_fsm<--- sip_call_id:%s" % (rcvd_message['Call-ID']['call_id'])
        # TODO Update the callstore to indicate next messages from this call will need to start at FSM in the forwarded awaiting ringback, etc...

    def proceeding_fsm(self, method, sip_ua, rcvd_message):
        print "-->proceeding_fsm<--"
        if method == "INVITE": #Send 100 Trying
            sip_ua.send_100Try(rcvd_message)
            # TODO Need next state to be a INVITE on the routing_response
            return "Forwarding", method

    def ring_fsm(self, method, sip_ua, rcvd_message):
        print "ring_fsm"
        if method == "INVITE": # TODO Send 180 Ringing here!
            sip_ua.send_180Ring(rcvd_message)
            return "Answering", method

    def answering_fsm(self, method, sip_ua, rcvd_message):
        print "answering_fsm" # TODO Request SDP from Dialogic
        if method == "INVITE":
            sip_ua.get_SDP(rcvd_message)
            return "WaitSDP", method

    def answer_fsm(self, method, sip_ua, rcvd_message):
        print "answer_fsm" # TODO Send 200 OK here!
        if method == "INVITE":
            sip_ua.send_200OK(rcvd_message)
            return "WaitACK", method # Really needs to be a state waiting for ACK

    def cancel_fsm(self, method, sip_ua, rcvd_message):
        print "cancel_fsm %s" % (method) # TODO Cancel and cleanup transaction
        if method == "INVITE" or method == "100 Trying" or method == "180 Ringing": # We can cleanup the call and respond as cancelled
            print("***Must be Cancelling our own call?")
        if method == "CANCEL":
            sip_ua.cancel_call(rcvd_message)
            return "Cancelled", method

    def acknowleged_fsm(self, method, sip_ua, rcvd_message):
        print "acknowleged_fsm"
        if method =="ACK":
            sip_ua.acknowleged_call(rcvd_message)
            return "InDialog", method

    def disconnecting_fsm(self, method, sip_ua, rcvd_message):
        print "disconnecting_fsm"
        if method =="BYE":
            sip_ua.disconnecting_call(rcvd_message)
            #return "Disconnected", method
            return "BYEWait4ACK", method

    def delete_fsm(self, method, sip_ua, rcvd_message):
        print "Log Info:--->delete_fsm<--- sip_call_id:%s" % (rcvd_message['Call-ID']['call_id'])
        sip_call_id = rcvd_message['Call-ID']['call_id']
        CallStore().delete_call(sip_call_id)
        return "Deleted", method

    def deleted_fsm(self, method, sip_ua, rcvd_message):
        print "Log Info:--->deleted_fsm<--- sip_call_id:%s" % (rcvd_message['Call-ID']['call_id'])

    def disconnected_fsm(self, method, sip_ua, rcvd_message):
        print "Log Info:--->disconnected_fsm<--- sip_call_id:%s" % (rcvd_message['Call-ID']['call_id'])
        return "Delete", method

    def cancelled_fsm(self, method, sip_ua, rcvd_message):
        print "Log Info:--->cancelled_fsm<--- sip_call_id:%s" % (rcvd_message['Call-ID']['call_id'])
        return "Delete", method

    def waiting_ack(self, method, sip_ua, rcvd_message):
        #if method =="BYE":
        print "waiting_ack"
        return "Delete", method

    def waiting_sdp(self, method, sip_ua, rcvd_message):
        print "waiting_sdp"

    def indialog_fsm(self, method, sip_ua, rcved_message):
        print "indialog_fsm"



