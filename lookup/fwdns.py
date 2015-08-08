
# Original purpose of this ansible lookup plugin is to help to generate variables for 
# Shorewall firewall by resolving domain addresses. 
# Other modules that I found lacked features such as support for IPv6 and creating 
# network addresses for subnets. 
# 
# Requires netaddr-module for address transformations.


import socket
import netaddr
from ansible import utils, errors


class LookupModule(object):
    '''
    Examples of supported parameter formats:
    'example.com'                       # Basic domain name
    'example.com/24'                    # Include netmask bits, network address is returned in CIDR
    'example.com/64 v=6'                # Define version for IP addresses to resolve,
                                        # choices for version are '4' and '6'.  Default is '4'.
    '''

    def __init__(self, basedir=None, **kwargs):
        self.basedir = basedir
        self._ipv6_suffix = ' v=6'

    def run(self, terms, variables=None, **kwargs):
        addresses = []

        if isinstance(terms, basestring):
            terms = [terms]

        for term in terms:
            socket_type = socket.AF_INET
            host = None
            netmask = None

            if term.endswith(self._ipv6_suffix):
                socket_type = socket.AF_INET6
                term = term[:-len(self._ipv6_suffix)]

            if '/' in term:
                host, netmask = term.split('/')
            else:
                host = term

            try:
                for info in socket.getaddrinfo(host, None, socket_type):
                    result = None

                    # Get only the IP address from the result
                    network = netaddr.IPNetwork(info[4][0])
                
                    if netmask is not None:
                        # Possible duplicates are removed at the end
                        network.prefixlen = int(netmask)
                        result = network.cidr
                    else:
                        result = network.ip

                    addresses.append(str(result))

            except:
                raise errors.AnsibleError('Exception while resolving "%r"' % (term,))


        # Remove duplicates and sort the list to keep changes in strings to a minimum
        addresses = list(set(addresses))
        addresses.sort()

        return addresses

