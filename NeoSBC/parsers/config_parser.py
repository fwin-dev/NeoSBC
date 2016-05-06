import logging
import ConfigParser

logger = logging.getLogger( 'serverLogger.ConfigParser' )

class ConfigProcesser():

    def __init__( self, config_file ):
        self.config_file = config_file
        self.config = ConfigParser.ConfigParser()

        self.__read_config()

    def __read_config( self ):
        with open( self.config_file ) as config_file:
            self.config.readfp( config_file )

    def process_config( self ):
        logger.info( 'Parsing configuration' )

        zone_list       = []
        data_instances  = 0

        for section in self.config.sections():

            if section == 'Data_Plane':  # For now we only support one data_plane per VM
                data_instances += 1

            if section[:4] == 'Zone':  # In a Zone section, must create it
                logger.info( 'Creating {} zone'.format( section[5:] ) )
                new_zone = {'zone_name': section[5:]}  # Assign our friendly name to this zone
                new_zone.update(dict(self.config.items(section)))  # Put the rest of our attributes in this dictionary
                zone_list.append(new_zone)
                logger.info( 'Zone {} appended to list'.format( new_zone['zone_name'] ) )
                logger.debug( 'Zone list: {}'.format( [zone['zone_name'] for zone in zone_list] ) )

            if section == 'Security':
                for security_rule in self.config.items(section):
                    # Need to evaluate all rules to see if we can lock down PF better
                    logger.debug( 'Security rule: {}'.format( security_rule ) )

        return zone_list, data_instances

