# region-configuration-tool
Python tool to create region configuration file for Eucalyptus 4.2 Federation

## Requirements
This tool requires the following:
* Digest algorithm used to sign Eucalyptus Cloud Certificate (default:  sha256)
* Cloud certificate from each cloud (i.e. region)
* Region name for each cloud (i.e. region).  This is ```region.region_name``` cloud property
* DNS Domain name for each cloud (i.e. region).  This is the ```system.dns.dnsdomain``` cloud property

## Output
This tool will provide a region configuration file that is intended to be uploaded to each cloud (i.e. region) as the ```region.region_configuration``` cloud property value using euca-modify-property. 

## Usage
### Options
The help output of region-config-tool.py:
```
# ./region-config-tool.py --help
usage: region-config-tool.py REGION [REGION ...] [-f | --filename] FILE_NAME

Script that creates region configuration file from multiple region (i.e.
cloud) parameters that are intended to be part of a federated environment.

optional arguments:
  -h, --help            show this help message and exit

Region Arguments:
  Arguments to define multiple regions

  region                Region defintion; multiple regions separated by
                        spaces; should contain the following format for each
                        entry: region_name=ParameterValue,cloud_cert=Parameter
                        Value,domain_name=ParameterValue. For each cloud (i.e.
                        region) - "region_name" should match
                        region.region_name cloud property; "cloud_cert" should
                        be the cloud certificate (/var/lib/eucalyptus/keys
                        /cloud-cert.pem) of the Cloud Controller for that
                        cloud (i.e. region); "domain_name" should match the
                        system.dns.dnsdomain cloud property

Region Configuration File Argument:
  Argument to define name of of generated region configuration file.

  -f FILE_NAME, --filename FILE_NAME
                        Generated region configuration file.

HTTP/HTTPS Protocol Flag Argument:
  Argument to set HTTP or HTTPS for Service Endpoints

  -p PROTOCOL, --protocol PROTOCOL
                        Flag to use HTTP/HTTPS for Service Endpoints. Default:
                        http

OpenSSL Signature Algorithm Argument:
  Argument that defines what OpenSSL signing alorithm was used for the cloud
  certificate

  -d DIGEST, --digest DIGEST
                        Digest algorithm used to sign cloud certificate.
                        Default: sha256
```

### Example
Example of using the region-config-tool.py
```
# ./region-config-tool.py region_name=foo,cloud_cert=at-long-last-asap-region.pem,domain_name=foo.eucalyptus-systems.com region_name=bar,cloud_cert=long-live-asap-region.pem,domain_name=bar.eucalyptus-systems.com -f test-region.json

## Contents of test-region.json ##
# cat test-region.json
{
    "Regions": [
        {
            "CertificateFingerprint": "ED:8F:9A:92:45:4D:37:F3:54:E4:2E:E7:26:28:EE:04:A1:DF:AD:82:87:60:A6:C3:4A:15:CB:D7:E9:F2:99:13",
            "CertificateFingerprintDigest": "SHA-256",
            "IdentifierPartitions": [
                1
            ],
            "Name": "foo",
            "Services": [
                {
                    "Endpoints": [
                        "http://identity.foo.eucalyptus-systems.com:8773/"
                    ],
                    "Type": "identity"
                },
                {
                    "Endpoints": [
                        "http://compute.foo.eucalyptus-systems.com:8773/"
                    ],
                    "Type": "compute"
                }
            ]
        },
        {
            "CertificateFingerprint": "3A:69:0F:B3:A5:03:92:50:39:F2:C6:EB:E5:77:94:36:F9:36:12:E2:01:CA:AB:75:B2:6E:71:9B:D0:5E:61:94",
            "CertificateFingerprintDigest": "SHA-256",
            "IdentifierPartitions": [
                2
            ],
            "Name": "bar",
            "Services": [
                {
                    "Endpoints": [
                        "http://identity.bar.eucalyptus-systems.com:8773/"
                    ],
                    "Type": "identity"
                },
                {
                    "Endpoints": [
                        "http://compute.bar.eucalyptus-systems.com:8773/"
                    ],
                    "Type": "compute"
                }
            ]
        }
    ]
}
```


