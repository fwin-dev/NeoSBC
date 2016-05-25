## Installation
If your systems default python version is 3 replace the python commands with python2

To install NeoSBC run python setup.py install

To install for development run python setup.py develop

## BIG TODOs

1. Move the Call_Store used to hold onto past messages and related states of the message/call into its own class
    and move operations on it to same class.(**Partially completed**)
2. Add CouchDB client and move the security rules to a dynamic storage model
3. Add Unicast Interfaces for communication between a pair of SBC instances and add appropriate distribution code to Call Store Class
4. Add REST based management interface to list calls and related structures, and statistics.

## next phase TODOs

### Milestone: Working SBC forwarding a call and involving MSRP proxy session establishment

1. Move State Machine for SIP into separate python file.(**Done**)
2. Finish Forwarding state logic
3. Move CallStore Class to separate python file.(**Done**)
4. Finish state machine drawings for all state logic threads
5. Remove XMS REST(XML) logic and replace with JSON for our MSRP proxy
6. Set detection for malicious SIP, e.g. not matching a permit string, after blackhole count reaches maximum threshold then push filter to FW
7. Move security tests over SIP to the security class... passing the SIP message and applicable rule_set from the seczone to evaluate.


### Future

1. Need to add a destination group concept for rules to point to, this ensures a form of SIP redundancy when UDP load balancing isn't used.
