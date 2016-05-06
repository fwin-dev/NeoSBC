# Standard Lib Imports
import logging
import logging.config
import os, signal
import socket

# NeoSBC Imports
from NeoSBC.security.packet_filter import PacketFilterInterface
from NeoSBC.parsers.config_parser import ConfigProcesser

__author__ = 'jkinney'
__version__ = '0.0.1'

logging.config.fileConfig( 'logger.conf' )

logger = logging.getLogger('serverLogger.control_plane')

data_instances = 0

# TODO Wrap this into function and do some error checking
configFile = 'config.cfg'



# Create our packet filter class instance

def interupt_handler( signum, frame ):
    logger.info( 'Server exiting' )
    sys.exit(0)

def process_zone(security_zone, working_rule_set):
    logger.info( 'Processing {} zone'.format( security_zone['zone_name'] ) )
    if 'fw_interface' in security_zone:
        logger.info( 'Finding firewall interface: {}'.format( security_zone['fw_interface'] ) )
        tmp_interface = find_interface(security_zone['fw_interface'])
        if tmp_interface is not None:
            logger.info( 'Found interface' )
            # We are using a Firewall with this SBC
            logger.info( 'Checking if nat enabled' )
            if 'nat_ip' in security_zone and 'nat_port' in security_zone:
                logger.info( 'Nat enabled creating rule' )
                # We have a nat enabeled interface
                tmp_rule = create_diversion_rule(security_zone['fw_interface'],
                        security_zone['nat_ip'],
                        security_zone['nat_port'],
                        security_zone['sip_ip'],
                        security_zone['sip_port'])
                working_rule_set.append(tmp_rule)
                logger.info( '{} appended to rule set'.format( tmp_rule ) )


# Based on our configuration we are going to start one or more Python data-planes

###################################################################################################

########################################## Main ###################################################
# TODO make a restart loop, but also need respawn too fast check
# Start data_plane(s)
def main():

    config          = ConfigProcesser( configFile )
    packet_filter   = PacketFilterInterface()
    #TODO Finish changing over to using the PacketFilterInterface

    zone_list, data_instances = config.process_config()

    signal.signal( signal.SIGINT, interupt_handler )

    if data_instances >= 1:
        logger.info('Starting data-planes')

        child_pid = os.fork()  # Time to fork, now time to start our data_plane
        logger.info( 'Process has been forked pid: {}'.format( child_pid ) )

        if child_pid == 0:  # I am the child, place to run data_plane
            logger.info( 'In the child process starting server' )
            # TODO Add support to give server.py the instance number, that can be matched to other config
            os.system('python ./server/server.py')  # simple starting data_plane, we can wrap to restart
            sys.exit(0)

        # Continue on with loading the Control_Plane
        working_rule_set = pf.PFRuleset(name='voip-proxy')

        # Now process zones and poke holes in firewall, the data plane is running.
        for security_zone in zone_list:
            process_zone(security_zone, working_rule_set)
            logger.info( 'Processing for {} zone done'.format( security_zone['zone_name'] ) )

        pfilter.load_ruleset(working_rule_set, path='voip-proxy')
        logger.info( 'Rule set loaded to packet filter' )

        # Verify our ruleset
        logger.debug( 'Packet filter rules: {}'.format( pfilter.get_ruleset( 'voip-proxy' ) ) )

        # Now wait for data_plane to exit
        pid, status = os.waitpid(child_pid, 0)
        logger.info('PID: %d, Status: %d' % (pid, status) )


if __name__ == '__main__':
    main()
