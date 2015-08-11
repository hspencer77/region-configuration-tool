#!/usr/bin/python -tt

import argparse
import re
import json


def get_options():
    """
    Function to grab commandline options to generate region configuration file
    from provided parameters.

    param:  None
    """
    def format_error(err_string):
        """
        Function to print standard formatting error for each region parameter
        provided.
       
        param:  err_string:  variable that has the incorrect format
        """
        msg = ("\nIncorrect Region \'key=value\' format - " + err_string + "\nPlease use "
               + "the following format: " + "\n" + "\t" +
               "region_name=ParameterValue,ip=ParameterValue," +
               "domain_name=ParameterValue") 
        return msg

    def region_check(region):
        """
        Function to check formatting of parameters passed for each region
        
        param:  region:  string that should contain the following format - 
                region_name=ParameterValue,ip=ParameterValue,domain_name=ParameterValue
        """
        # Check each region has correct number of parameters
        try:
            region_name, ip, domain_name = region.split(',')        
        except ValueError:
            msg = format_error(region)
            raise argparse.ArgumentTypeError(msg)
        
        # Check that each parameter is the proper key=value format
        for param in [ region_name, ip, domain_name ]:
            try:
                key_param, value_param = param.split('=')
            except ValueError: 
                msg = format_error(region)
                raise argparse.ArgumentTypeError(msg)
            
            if not any(key_param in key for key in ["region_name", "ip", "domain_name"]):
                msg = format_error(region)
                raise argparse.ArgumentTypeError(msg)

        # Check for proper length and valid region name
        region_key, region_value = region_name.split('=')
        if not re.match("^(?![0-9]+$)(?!-)[a-zA-Z0-9-]{,63}(?<!-)$", region_value):
            msg = format_error(region)
            region_msg = ("\n\n" + region_key + " has a value which is not a valid DNS label." +
                          " Please refer to <label> definition for RFC 1035 " +
                          "https://www.ietf.org/rfc/rfc1035.txt.")
            raise argparse.ArgumentTypeError(msg + region_msg)
        
        # Check for proper IPv4 format      
        ip_key, ip_value = ip.split('=')
        if not re.findall(
                         r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
                         ip_value):
            msg = format_error(region)
            ip_msg = ("\n\n" + ip_key + " has a value which is not a valid IPv4 address.")
            raise argparse.ArgumentTypeError(msg + ip_msg)

        # Check for proper domain/subdomain format 
        domain_key, domain_value = domain_name.split('=')
        if not re.findall(
                         r'^[a-zA-Z\d-]{,63}(\.[a-zA-Z\d-]{,63})*$',
                         domain_value):
            msg = format_error(region)
            domain_msg = ("\n\n" + domain_key + " has a value which is not a value DNS domain. " +
                          "Please refer to the <domain> definition in RFC 1035 " +
                          "https://www.ietf.org/rfc/rfc1035.txt.")
            raise argparse.ArgumentTypeError(msg + domain_msg)

        return region

    def http_check(protocol):
        """
        Function to confirm if protocol is either http or https
  
        param:  protocol: Define http or https protocol
        """
        if not re.match('^http$|^https$', protocol, re.I):
            msg = ("\n\nPROTOCOL is not in the correct format. " +
                   "Accepted values: \'http\' or \'https\'. " +
                   "Default value: \'http\'.")
            raise argparse.ArgumentTypeError(msg)

        return protocol
                   
    parser = argparse.ArgumentParser(prog="region-config-tool.py",
                 usage='%(prog)s REGION [REGION ...] [-f | --filename] FILE_NAME',
                 description='Script that creates region configuration file from \
                 multiple region (i.e. cloud) parameters that are intended to be \
                 part of a federated environment.')
    region_group = parser.add_argument_group("Region Arguments", "Arguments to define multiple regions")
    region_group.add_argument('region', nargs='+', type=region_check, 
                              help='Region defintion; \
                              multiple regions separated by spaces; should \
                              contain the following format for each entry: \
                              region_name=ParameterValue,ip=ParameterValue,domain_name=ParameterValue.\
                              For each cloud (i.e. region) - \"region_name\" should match \
                              region.region_name cloud property; \"ip\" should be \
                              the IP of the Cloud Controller; \"domain_name\" should match the \
                              system.dns.dnsdomain cloud property')
    file_group = parser.add_argument_group("Region Configuration File Argument", 'Argument to define name of \
                                           of generated region configuration file.') 
    file_group.add_argument('-f', '--filename', dest='file_name', 
                            type=argparse.FileType('w'),
                            help="Generated region configuration file.")
    http_option = parser.add_argument_group("HTTP/HTTPS Protocol Flag Argument",
                                            "Argument to set HTTP or HTTPS for Service Endpoints")
    http_option.add_argument('-p', '--protocol', dest='protocol',
                             type=http_check, default='http',
                             help="Flag to use HTTP/HTTPS for Service Endpoints. Default: http")
    options = parser.parse_args()
    return options

if __name__ == "__main__":
    # Grab commandline options for region configuration
    options = get_options()
    region_config = {'Regions': []}
    for region in options.region:
        region_name, ip, domain_name = region.split(',')
        identifier = options.region.index(region) + 1
        region_config['Regions'].append({
            'Name': region_name.split('=')[1],
            'CertificateFingerprintDigest': 'SHA-256',
            'CertificateFingerprint': '',
            'IdentifierPartitions': [ identifier ],
            'Services': [
                {
                 'Type': 'identity',
                 'Endpoints': [ options.protocol + '://identity.' + domain_name.split('=')[1] + ':8773/' ]
                },
                {
                 'Type': 'compute',
                 'Endpoints': [ options.protocol + '://compute.' + domain_name.split('=')[1] + ':8773/' ]
                }
             ]
         })
           
    with options.file_name as json_file:
        json.dump(region_config, json_file, sort_keys=True,
                  indent=4, separators=(',', ': '))
    json_file.closed
