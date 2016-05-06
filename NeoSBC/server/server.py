#!/usr/local/bin/python

import logging
import logging.config
#import string, sys, re, os
import ConfigParser
from twisted.internet.endpoints import TCP4ServerEndpoint
# from twisted.internet import reactor

# from pprint import pformat
# from zope.interface import implements
# from xml.sax.saxutils import escape
# from xml.sax.saxutils import unescape
#
# from xml.dom.minidom import parseString
#
# from statemachine import StateMachine
#
# from twisted.internet.protocol import DatagramProtocol
# from twisted.internet import reactor
# from twisted.internet.protocol import Protocol
#
# # For our REST Client used towards XMS
# from twisted.web.client import Agent
# from twisted.internet.defer import Deferred
#
# from rest import *

# Need to change these to use classes
from NeoSBC.userAgent.sip_UA import *
from NeoSBC.security.security import *
from NeoSBC.server.redundancy import *

__author__ = 'jkinney'
__version__ = '0.0.2'

logging.config.fileConfig( 'logger.conf' )
logger = logging.getLogger( 'serverLogger.server' )

# Setup our storage for interfaces
interface_store = {}
security_rule_list = []

configFile = 'config.cfg'
config = ConfigParser.ConfigParser()
config.readfp(open(configFile))

logger.info( 'Parsing config file: {}'.format( configFile ) )

for section in config.sections():
    if section[:4] == 'Zone': # In a Zone section, must create it
        logger.info( 'Creating {} zone'.format( section[5:] ) )
        new_zone = {'interface_name': section[5:]}
        new_zone.update(dict(config.items(section)))

        logger.info( 'Starting to listen to port {} on {}'.format( new_zone['sip_port'], new_zone['sip_ip'] ) )
        reactor.listenUDP(int(new_zone['sip_port']), SIP_UA(security_rule_list, new_zone['seczone']), interface=new_zone['sip_ip'])
        interface_store.update({new_zone['seczone']: new_zone})
        logger.info( 'Added {} to interface_store'.format( new_zone['seczone'] ) )
    if section == 'Security':
        logger.info( 'Parsing rules' )
        for security_rule in config.items(section):
            logger.debug( 'Rule: {}'.format( security_rule ) )
            parse_rule(security_rule_list, security_rule)
    if section == 'Redundancy':
        direct_item = dict(config.items(section))
        for item in config.items(section):
            item_name, item_value = item
            if item_name == "startup" and item_value == "primary":  # Listen for backup to connect
                logger.info( 'Connecting to backup port: {}'.format( direct_item['listener_port'] ) )
                endpoint = TCP4ServerEndpoint(reactor, int(direct_item['listener_port']),
                                              interface=direct_item['listener_ip'])
                endpoint.listen(RedundancyFactory())
                logger.info( 'Backup is setup' )
            else:  # Connect to
                logger.info( 'Next is Client' )

logger.debug( 'Current security rules: {}'.format( security_rule_list ) )

logger.info( 'Server started' )
reactor.run()
