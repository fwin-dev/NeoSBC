from setuptools import setup

setup(
        name            = 'NeoSBC',
        version         = '0.0.1',
        description     = 'Python SBC',
        url             = 'holder',
        author          = 'James Kinney, Mark Boger',
        author_email    = '',
        license         = 'GPLv3',
        packages        = [ 'NeoSBC', 'NeoSBC/constructors', 'NeoSBC/parsers',
                            'NeoSBC/security', 'NeoSBC/server', 'NeoSBC/stateMachine', 'NeoSBC/storage',
                            'NeoSBC/userAgent'],
        zip_safe        = False
        )
