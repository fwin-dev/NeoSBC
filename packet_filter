import logging
import pf, sys, errno


__author__  = 'Mark Boger'
__version__ = '0.0.1'

logger = logging.getLogger( 'securityLogger.PacketFilterInterface' )

class PacketFilterInterface:


    def __init__( self ):
        self.__enable_pf()

    def __enable_pf( self ):
        self.pfilter = pf.PacketFilter()
        self.interfaces  = {}
        self.rule_list   = []
        try:
            self.pfilter.enable()
            logger.info( 'Packet filtering has been enabled' )
        except IOError, (err, msg):
            if err == errno.EACCES:
                logger.error( 'Permission denied for packet filter ' )
                sys.exit( 'Permission denied: are you root?' )
            elif err == errno.ENOTY:
                logger.error( 'IOCTL not supported by device' )
                sys.exit( 'IOCTL not supported by device: is the device correct?' )

    def find_interface( self, iface_name ):
        if not self.interfaces:
            self.__populate_ifaces()

        logger.info( 'Finding interface: {}'.format( iface_name ) )

        if iface_name in self.interfaces.keys():
            piface = self.pfilter.get_ifaces( iface_name )
            logger.info( 'Found interface' )
        else:
            logger.error( 'Unable to find interface: {}'.format( iface_name ) )
            return None

        logger.debug( 'piface: {}'.format( piface ) )
        return piface

    def __populate_ifaces( self ):
        for iface in self.pfilter.get_ifaces():
            self.interfaces[iface._to_string().split()[0]] = iface

        logger.debug( 'Available interfaces: {}'.format( self.interfaces.keys() ) )

    def create_diversion_rule( self, iface, nat_ip, nat_port, sip_ip, sip_port ):
        logger.info( 'Making diversion rule' )
        if nat_ip is not None:
            logger.info( 'Making PFRuleAddr using {} at port {} '.format( nat_ip, nat_port ) )
            tmp_dst = pf.PFRuleAddr(pf.PFAddr(nat_ip), pf.PFPort(nat_port, socket.IPPROTO_UDP))
            logger.info( 'Made PFRuleAddr: {}'.format( tmp_dst ))
        elif nat_ip is None and nat_port is not None:
            logger.info( 'Making PFRuleAddr without nat ip using port {}'.format( nat_port ) )
            tmp_dst = pf.PFRuleAddr(None, pf.PFPort(nat_port, socket.IPPROTO_UDP))
            logger.info( 'Made PFRuleAddr: {}'.format( tmp_dst ))
        else:
            logger.warn( 'Not enough detail to open firewall' )
            return None  # Not enough detail to open firewall

        logger.info( 'Making PFRule' )
        tmp_rule = pf.PFRule(action=pf.PF_PASS,
                             direction=pf.PF_IN,
                             quick=True,
                             ifname=interface,
                             af=socket.AF_INET,
                             proto=socket.IPPROTO_UDP,
                             dst=tmp_dst,
                             keep_state=pf.PF_STATE_NORMAL,
                             divert=(pf.PFAddr(sip_ip), pf.PFPort(sip_port, socket.IPPROTO_UDP)))
        logger.info( 'Made PFRule: {}'.format( tmp_rule ) )
        return tmp_rule

    def load_ruleset( self, rule_path ):
        self.pfilter.load_ruleset( self.rule_list, path=rule_path )
