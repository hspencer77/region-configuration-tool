#!/usr/bin/python -tt

import argparse
import re
import json
import os
import subprocess


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
                region_name=ParameterValue,cloud_cert=ParameterValue,domain_name=ParameterValue
        """
        # Check each region has correct number of parameters
        try:
            region_name, cloud_cert, domain_name = region.split(',')        
        except ValueError:
            msg = format_error(region)
            raise argparse.ArgumentTypeError(msg)
        
        # Check that each parameter is the proper key=value format
        for param in [ region_name, cloud_cert, domain_name ]:
            try:
                key_param, value_param = param.split('=')
            except ValueError: 
                msg = format_error(region)
                raise argparse.ArgumentTypeError(msg)
            
            if not any(key_param in key for key in ["region_name", "cloud_cert", "domain_name"]):
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

        # Check that cloud cert is a file
        cloud_key, cloud_value = cloud_cert.split('=')
        if not os.path.isfile(cloud_value):
            msg = format_error(region)
            cloud_msg = ("\n\n" + cloud_key + " has a value which is not a file.")
            raise argparse.ArgumentTypeError(msg + cloud_msg)

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

    def digest_check(digest):
        """
        Function to confirm if digest meets the supported formats described
        here:  https://www.openssl.org/docs/apps/openssl.html#MESSAGE-DIGEST-COMMANDS
        Formats supported by Eucalyptus Federation: sha1, sha224, sha256, sha384, sha512

        param: digest: OpenSSL digest algorithm
        """
        if not re.match('^sha(1$|224$|256$|384$|512$)',
                        digest,
                        re.I):
            msg = ("\n\nDIGEST is not in the correct format. " +
                   "Accepted values: " +
                   "sha1, sha224, sha256, sha384, or sha512." +
                   "Default value: sha256")
            raise argparse.ArgumentTypeError(msg)
        return digest
                   
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
                              region_name=ParameterValue,cloud_cert=ParameterValue,domain_name=ParameterValue.\
                              For each cloud (i.e. region) - \"region_name\" should match \
                              region.region_name cloud property; \"cloud_cert\" should be \
                              the cloud certificate (/var/lib/eucalyptus/keys/cloud-cert.pem) of the Cloud \
                              Controller for that cloud (i.e. region); \"domain_name\" should match the \
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
    cert_fingerprint = parser.add_argument_group("OpenSSL Signature Algorithm Argument",
                                                 "Argument that defines what OpenSSL signing alorithm " +
                                                 "was used for the cloud certificate")
    cert_fingerprint.add_argument('-d', '--digest', dest='digest',
                                  type=digest_check, default='sha256',
                                  help="Digest algorithm used to sign cloud certificate. Default: sha256")
    options = parser.parse_args()
    return options

def local(cmd):
    """
    Function that executes commandline calls in the bash shell

    param:  cmd:  command to be executed in the shell
    """
    args = cmd.split()
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=4096)
    output, unused_err = process.communicate()
    retcode = process.poll()
    if retcode:
        error = subprocess.CalledProcessError(retcode, cmd)
        msg = ("\n\nCloud Certificate does not match message digest " +
               "or there is an issue with the openssl command.")
        error.output = output
        print msg + "\n"
        raise error
    return output.split("\n")

def verify_fingerprint(digest, cloud_cert):
    """
    Function to grab fingerprint using digest and cloud certificate

    param:  digest:  OpenSSL digest algorithm
    param:  cloud_cert:  Eucalyptus Cloud Certificate
    """
    fingerprint_cmd = ("openssl x509 -inform PEM -in " + cloud_cert + 
                       " -noout -fingerprint -" + digest)
    fingerprint_check = local(fingerprint_cmd)
    return fingerprint_check[0].split('=')[1]    
    

if __name__ == "__main__":
    # Grab commandline options for region configuration
    options = get_options()
    # Generate CertificateFingerprintDigest in accepted format
    digest = re.match('^sha(1$|224$|256$|384$|512$)', options.digest)
    digest_alg = 'SHA-' + digest.group(1)
    # Initialize region configuration file
    region_config = {'Regions': []}
    for region in options.region:
        """
        For each region entry, grab 'region_name', 'cloud_certificate', 
        and 'domain_name'
        """
        region_name, cloud_cert, domain_name = region.split(',')
        identifier = options.region.index(region) + 1
        digest_fingerprint = verify_fingerprint(options.digest,
                                                cloud_cert.split('=')[1])
        region_config['Regions'].append({
            'Name': region_name.split('=')[1],
            'CertificateFingerprintDigest': digest_alg,
            'CertificateFingerprint': digest_fingerprint,
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
           
    # Dump JSON data into file
    try:
        with options.file_name as json_file:
            json.dump(region_config, json_file, sort_keys=True,
                      indent=4, separators=(',', ': '))
        json_file.closed
    except:
        raise AttributeError("Missing -f|--filename option") 
