import logging
from twisted.internet.protocol import Protocol
from twisted.internet.protocol import Factory
from NeoSBC.storage.callstore import *

__author__ = 'jkinney'


class RedundancyFactory(Factory):

    def buildProtocol(self, addr):
        return Redundancy(Factory)


# TODO Work on better protocol syntax, this is just simple string for now
class Redundancy(Protocol):

    __command_pattern = {'assign_call': CallStore().assign_call,
                         'add_call_fragment': CallStore().add_call_fragment}

    def __init__(self, factory):
        self.factory = factory

    def changeMade(self, rpc_command, direction, call_record_key, payload):
        self.transport.write(rpc_command + " " + direction + " " + call_record_key + " " +
                             str(payload) + "\r\n")  # Write out our representation of data

    def connectionMade(self):
        CallStore().subscribe(self.changeMade)  # Register our callback to send a change
        self.transport.write("SBC_READY\r\n")  # Remove this eventually, human comfort for now

    def connectionLost(self, reason):
        print "Disconnected partner"

    # Command = <command> <direction> <call_record_key> <{data}>
    # Method = (direction, call_record_key, data, remote=True)
    def dataReceived(self, data):
        data_list = str.split(data)  # Split up our string into tokens.

        # Actions that print out data
        if data_list[0][:4] == "dump":
            if data_list[0] == "dump_call":
                payload = CallStore().dump_call(data_list[1], data_list[2])
                self.transport.write(str(payload) + "\r\n")
            result = False
        else:  # All other commands that affect the call store
            result = self.__command_pattern[data_list[0]](data_list[1], data_list[2], data_list[3], remote=True)

        if result:
            print "Yeeha!!!!!!!!!!!!!!!!!!!!!!!!!!"



# Tests
if __name__ == '__main__':
    #  TODO Finish tests
    data = "create_call kr9acohdv9oqvpt72ocj {'z9hG4bKaff4.6e3fcac39b9eb944cfbc536a98e9d9be.0': {'branch_id': " \
           "'z9hG4bKaff4.6e3fcac39b9eb944cfbc536a98e9d9be.0', 'seczone': 'outside', 'current_state': 'INITIAL', " \
           "'fragments': [], 'call_id': 'kr9acohdv9oqvpt72ocj'}}"
    test = Redundancy(RedundancyFactory())
    test.dataReceived(data)
