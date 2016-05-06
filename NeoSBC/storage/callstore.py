import logging
from threading import Event
import ast

__author__ = 'jkinney'


# Singleton Style Class that is used for safe and resilient storage of call data
class CallStore:
    instance = None


    class __CallStore:
        def __init__(self):
            self.callbacks = []
            self.ingress_call_list = []  # TODO, we maybe can just put empty list in dictionary below
            self.egress_call_list = []
            self.ingress_call_store = {'call_list': self.ingress_call_list}
            self.egress_call_store = {'call_list': self.egress_call_list}

            self.__call_store = {'ingress': self.ingress_call_store,
                                 'egress': self.egress_call_store}

            self.call_list = []  # TODO remove when ingress/egress replaces call_store
            self.call_store = {'call_list': self.call_list}  # TODO remove when ingress/egress replaces call_store


    # TODO Add the option to indicate the ip and port for pushing to
    # TODO a remote connection add, update and delete actions with meta-data for calls
    def __init__(self):
        if not CallStore.instance:
            CallStore.instance = CallStore.__CallStore()

    def __getattr__(self, item):
        return getattr(self.instance, item)

    def subscribe(self, callback):
        print "******************CallBack Here********************"
        self.callbacks.append(callback)

    def fire(self, rpc_command, direction, call_record_key, payload):
        for fn in self.callbacks:
            fn(rpc_command, direction, call_record_key, payload)

    def find_record(self, direction, call_record_key):
        call_store = self.__call_store[direction]

        if call_record_key in call_store['call_list']:
            call_record = call_store[call_record_key]  # Should have our call, now lets see if a branch is involved.
            return call_record
        else:
            return None

    def assign_call(self, direction, call_record_key, call_record, remote=False):
        call_store = self.__call_store[direction]

        if isinstance(call_record, basestring):  # If our call_record is a string make it a dict
            call_record = ast.literal_eval(call_record)

        existing_record = self.find_record(direction, call_record_key)
        if existing_record is None:  # Ok, good deal, we didn't want to try to create a call that existed.
            call_store["call_list"].append(call_record_key)
            call_store[call_record_key] = call_record
            if not remote:
                self.fire('assign_call', direction, call_record_key, call_record)
            return True
        else:
            return False

    # Dump full call record, this could just be find_record for that matter, but maybe more friendly this way
    def dump_call(self, direction, call_record_key):
        result = self.find_record(direction, call_record_key)
        print "Log Info:--->CallStore.dump_call<--- direction:%s, call_record_key:%s" % (direction, call_record_key)
        return result

    def dump_all_calls(self):
        print "Log Info:--->CallStore.dump_all_calls<---"

    # Add call fragment
    def add_call_fragment(self, direction, call_record_key, call_fragment, remote=False):
        call_store = self.__call_store[direction]

        if isinstance(call_fragment, basestring):
            call_fragment = ast.literal_eval(call_fragment)

        if call_record_key in call_store['call_list']:
            call_store[call_record_key]['fragments'].append(call_fragment)
            if not remote:
                self.fire('add_call_fragment', direction, call_record_key, call_fragment)



    def update_routing(self, direction, call_id, routing):
        call_store = self.__call_store[direction]



    # Add a call fragment to the call store
    def add_call(self, sip_call_id, call_fragment):
        print "Log Info:--->CallStore.add_call<--- sip_call_id=" + sip_call_id
        # Add our Call-ID to the list
        self.instance.call_store["call_list"].append(sip_call_id)
        # Add our last method to the call store for distribution and state change
        self.instance.call_store[sip_call_id] = call_fragment

    # Find a call and return its dictionary object
    def find_call(self, sip_call_id):
        # Start out with None Object to flag a not found
        call_record = None

        print "Log Info:--->CallStore.find_call<--- sip_call_id=" + sip_call_id
        if sip_call_id in self.instance.call_store['call_list']:
            call_record = self.instance.call_store[sip_call_id]  # Retrieve our call record

        return call_record

    def call_exists(self, sip_call_id):
        if sip_call_id in self.instance.call_store['call_list']:
            return True
        else:
            return False

    def update_call(self, sip_call_id, call_fragment):
        if sip_call_id in self.instance.call_store['call_list']:
            self.instance.call_store[sip_call_id] = call_fragment

    def delete_call(self, sip_call_id):
        if sip_call_id in self.instance.call_store['call_list']:
            # Delete the key from the dictionary
            del self.instance.call_store[sip_call_id]
            # Remove the call from the list.
            self.instance.call_store['call_list'].remove(sip_call_id)

# Tests
if __name__ == '__main__':
    #  TODO Finish tests
    def call_back(rpc_command, direction, call_record_key, payload):
        print "Remote:" + rpc_command + " " + direction + " " + call_record_key
        Logging().LogDict('INFO', 'Test:CallStore() Callback', payload)

    CallStore().subscribe(call_back)
    call_fragment1 = """{'body': {'application/sdp': [['v', '0'], ['o', 'bob 3648376822 3648376822 IN IP4 192.168.56.172'], ['s', ' '], ['c', 'IN IP4 192.168.56.172'], ['t', '0 0'], ['m', 'message 2855 TCP/MSRP *'], ['a', 'accept-types:text/plain'], ['a', 'path:msrp://192.168.56.172:9000/581f653-7ff-24;tcp msrp://370ew4p7.invalid:2855/ckkvc3ndlm;ws'], ['a', 'oldmediaip:370ew4p7.invalid'], ['a', 'oldmediaip:370ew4p7.invalid']]}, 'Content-Length': {'content_length': 310}, 'Via': [{'attributes': 'branch=z9hG4bKf13c.e06b3c08e9ebaed7b8c13049fc7c764b.0', 'host': '192.168.56.172', 'port': None, 'transport': 'UDP'}, {'attributes': 'rport=55762;received=192.168.56.1;branch=z9hG4bK5003909', 'host': '2ibvhsmjjqm5.invalid', 'port': None, 'transport': 'WS'}], 'r_uri': 'sip:bob@192.168.56.176', 'Content-Type': {'content_type': 'application/sdp'}, 'Supported': {'header_value': 'path,outbound,gruu,tdialog'}, 'REQUEST': 'INVITE', 'User-Agent': {'user_agent': 'Crocodile SDK v<%= pkg.version %>; JsSIP 0.3.0-crocodile-1-devel; Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.124 Safari/537.36'}, 'sanity': True, 'To': {'uri': '<sip:bob@192.168.56.176>'}, 'From': {'uri': '<sip:bob@openrpr.org>;tag=mmcd5pqf2g'}, 'Contact': {'uri': '<sip:1v48jq01@2ibvhsmjjqm5.invalid;alias=192.168.56.1~55762~5;transport=ws;ob>;audio;video;text;data;+croc.sdkversion="<1>"'}, 'CSeq': {'method': 'INVITE', 'sequence_number': 8035}, 'Allow': {'header_value': 'ACK,CANCEL,BYE,OPTIONS,NOTIFY,INVITE,UPDATE,REFER'}, 'Call-ID': {'call_id': 'kr9ac4nph3cl3imr3077'}, 'Max-Forwards': {'max_forwards': 16}, 'Record-Route': {'uri': 'sip:192.168.56.172:8080;transport=ws;r2=on;lr=on'}, 'type': 'REQUEST'}"""
    CallStore().create_call("ingress", "outside", "01234_567890", call_fragment1)

    call_fragment2 = """{'Content-Length': {'content_length': 0}, 'Via': [{'attributes': 'branch=z9hG4bKf13c.e06b3c08e9ebaed7b8c13049fc7c764b.0', 'host': '192.168.56.172', 'port': None, 'transport': 'UDP'}], 'r_uri': 'sip:bob@192.168.56.176', 'REQUEST': 'CANCEL', 'sanity': True, 'To': {'uri': '<sip:bob@192.168.56.176>'}, 'From': {'uri': '<sip:bob@openrpr.org>;tag=mmcd5pqf2g'}, 'CSeq': {'method': 'CANCEL', 'sequence_number': 8035}, 'Call-ID': {'call_id': 'kr9ac4nph3cl3imr3077'}, 'Max-Forwards': {'max_forwards': 16}, 'type': 'REQUEST'}"""
    CallStore().add_call_fragment("ingress", "01234_567890", call_fragment2)
    CallStore().add_call_fragment("ingress", "01234_567890", call_fragment2)
    CallStore().add_call_fragment("ingress", "01234_567890", call_fragment2)
    CallStore().add_call_fragment("ingress", "01234_567890", call_fragment2)
    CallStore().add_call_fragment("ingress", "01234_567890", call_fragment2)

    Logging().LogCall('INFO', 'Test:CallStore().dump_call', CallStore().dump_call("ingress", "01234_567890"))
