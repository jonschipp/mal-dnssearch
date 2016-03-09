#!/usr/bin/python
#
# Aaron Eppert
#
# September 28, 2015        Initial Release                             Aaron Eppert
# September 29, 2015        Dynamic header creation and field filling   Aaron Eppert
# March 9, 2016             Added '-S' option to strip URIs and         Aaron Eppert
#                           removed '-T' option so a mixed type file
#                           may be supplied and heuristics generate the
#                           required type

import os
import re
import sys
import string
import socket
from urlparse import urlparse

from optparse import OptionParser, OptionGroup
from optparse import HelpFormatter as fmt


def warning(text):
    sys.stderr.write("WARNING: %s\n" % (text))


def error(text):
    sys.stderr.write("ERROR: %s\n" % (text))
    sys.exit(1)


def decorate(fn):
    def wrapped(self=None, desc=""):
        return '\n'.join([fn(self, s).rstrip() for s in desc.split('\n')])
    return wrapped
fmt.format_description = decorate(fmt.format_description)


class bro_intel_indicator_type:
    def __init__(self, strip_uri=False):
        self.__INDICATOR_TYPE_unsupported = ['Intel::SOFTARE',
                                             'Intel::USER_NAME',
                                             'Intel::FILE_NAME',
                                             'Intel::CERT_HASH']

        self.__INDICATOR_TYPE_handler = [(self.__handle_intel_addr,      'Intel::ADDR'),
                                         (self.__handle_intel_domain,    'Intel::DOMAIN'),
                                         (self.__handle_intel_url,       'Intel::URL'),
                                         (self.__handle_intel_email,     'Intel::EMAIL'),
                                         (self.__handle_intel_file_hash, 'Intel::FILE_HASH')]

    def __is_valid_ipv6_address(self, address):
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error:  # not a valid address
            return False
        return True

    def __is_valid_ipv4_address(self, address):
        try:
            socket.inet_pton(socket.AF_INET, address)
        except AttributeError:  # no inet_pton here, sorry
            try:
                socket.inet_aton(address)
            except socket.error:
                return False
            return address.count('.') == 3
        except socket.error:  # not a valid address
            return False
        return True

    def __handle_intel_addr(self, indicator):
        ret = (False, None)
        if self.__is_valid_ipv4_address(indicator) or self.__is_valid_ipv6_address(indicator):
            ret = (True, 'Intel::ADDR')
        return ret

    # We will call this minimalist, but effective.
    def __handle_intel_url(self, indicator):
        ret = (False, None)

        t_uri_present = re.findall(r'^https?://', indicator)
        if t_uri_present is not None and len(t_uri_present) > 0:
            error('Aborting - URI present (e.g. http(s)://) - %s' % (indicator))
        else:
            rx = re.compile(r'^[https?://]?'  # http:// or https://
                            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
                            r'localhost|'  # localhost...
                            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
                            r'(?::\d+)?'  # optional port
                            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
            t = rx.search(indicator)
            if t:
                ret = (True, 'Intel::URL')
        return ret

    def __handle_intel_email(self, indicator):
        ret = (False, None)
        rx = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        t_email = re.findall(rx, indicator)
        if len(t_email) > 0:
            ret = (True, 'Intel::EMAIL')
        return ret

    def __handle_intel_domain(self, indicator):
        ret = (False, None)
        rx = r'(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)'
        t_domain = re.findall(rx, indicator)
        if len(t_domain) > 0:
            if indicator in t_domain[0]:
                ret = (True, 'Intel::DOMAIN')
        return ret

    # Pretty weak, but should suffice for now.
    def __handle_intel_file_hash(self, indicator):
        ret = (False, None)
        VALID_HASH_LEN = {32: 'md5',
                          40: 'sha1',
                          64: 'sha256'}
        if VALID_HASH_LEN.get(len(indicator), None):
            ret = (True, 'Intel::FILE_HASH')
        return ret

    def determine(self, indicator):
        for ith in self.__INDICATOR_TYPE_handler:
            (t_okay, t_val) = ith[0](indicator)

            if t_okay:
                return t_val
        error("Could not determine indicator type for %s" % (indicator))


class mal_dns2bro:
    def __init__(self, args_dict):
        self.args_dict = args_dict
        self.append_intel_line = None
        self.sorted_hdr = [(0, '#fields',   None),
                           (1, 'indicator', None),
                           (2, 'indicator_type',      None)]

        self.if_in = ['-',
                      'Conn::IN_ORIG',
                      'Conn::IN_RESP',
                      'Files::IN_HASH',
                      'Files::IN_NAME',
                      'DNS::IN_REQUEST',
                      'DNS::IN_RESPONSE',
                      'HTTP::IN_HOST_HEADER',
                      'HTTP::IN_REFERRER_HEADER',
                      'HTTP::IN_USER_AGENT_HEADER',
                      'HTTP::IN_X_FORWARDED_FOR_HEADER',
                      'HTTP::IN_URL',
                      'SMTP::IN_MAIL_FROM',
                      'SMTP::IN_RCPT_TO',
                      'SMTP::IN_FROM',
                      'SMTP::IN_TO',
                      'SMTP::IN_RECEIVED_HEADER',
                      'SMTP::IN_REPLY_TO',
                      'SMTP::IN_X_ORIGINATING_IP_HEADER',
                      'SMTP::IN_MESSAGE',
                      'SSL::IN_SERVER_CERT',
                      'SSL::IN_CLIENT_CERT',
                      'SSL::IN_SERVER_NAME',
                      'SMTP::IN_HEADER']

        self._bitt = bro_intel_indicator_type()

        self.option_to_header = [('#fields',         '#fields',             lambda: None),
                                 ('indicator',       'indicator',           lambda: None),
                                 ('type',            'indicator_type',      lambda: None),
                                 ('source',          'meta.source',         self.__source),
                                 ('url',             'meta.url',            self.__url),
                                 ('notice',          'meta.do_notice',      self.__notice),
                                 ('if_in',           'meta.if_in',          self.__if_in),
                                 ('whitelist',       'meta.whitelist',      self.__whitelist),
                                 ('desc',            'meta.desc',           self.__desc),
                                 ('cif_severity',    'meta.cif_severity',   self.__cif_severity),
                                 ('cif_impact',      'meta.cif_impact',     self.__cif_impact),
                                 ('cif_confidence',  'meta.cif_confidence', self.__confidence)]

    def __verify_chars(self, t):
        return all(ord(l) > 31 and ord(l) < 127 and l in string.printable for l in t)

    def __find_header_order(self, t):
        ret = -1
        try:
            ret = map(lambda x: x[0], self.option_to_header).index(t)
        except ValueError:
            error('Invalid header!')
        return ret

    def __cif_severity(self):
        ret = ''
        VALID_SEVERITY = ['low', 'medium', 'med', 'high']
        if self.args_dict['cif_severity'] in VALID_SEVERITY:
            ret = self.args_dict['cif_severity']
        else:
            ret = '-'
        return (self.__find_header_order('cif_severity'), ret)

    def __cif_impact(self):
        ret = ''
        if self.args_dict['cif_impact'] is not None and len(self.args_dict['cif_impact']) > 0 and self.__verify_chars(self.args_dict['cif_impact']):
            ret = self.args_dict['cif_impact']
        else:
            ret = '-'
        return (self.__find_header_order('cif_impact'), ret)

    def __desc(self):
        ret = ''
        if self.args_dict['desc'] is not None and len(self.args_dict['desc']) > 0 and self.__verify_chars(self.args_dict['desc']):
            ret = self.args_dict['desc']
        else:
            ret = '-'
        return (self.__find_header_order('desc'), ret)

    def __if_in(self):
        ret = ''
        if self.args_dict['if_in'] is not None and len(self.args_dict['if_in']) > 0 and self.args_dict['if_in'] in self.if_in:
            ret = self.args_dict['if_in']
        else:
            ret = '-'
        return (self.__find_header_order('if_in'), ret)

    def __notice(self):
        ret = 'F'
        _to_bro = {'true':  'T',
                   'false': 'F'}
        if self.args_dict['notice'] is not None and _to_bro.get(self.args_dict['notice'], None) is not None:
            ret = _to_bro.get(self.args_dict['notice'])
        return (self.__find_header_order('notice'), ret)

    def __source(self):
        ret = ''
        if self.args_dict['source'] is not None and len(self.args_dict['source']) > 0 and self.__verify_chars(self.args_dict['source']):
            ret = self.args_dict['source']
        else:
            ret = 'mal-dnssearch'
        return (self.__find_header_order('source'), ret)

    def __url(self):
        ret = ''
        if self.args_dict['url'] is not None and len(self.args_dict['url']) > 0 and self.__verify_chars(self.args_dict['url']):
            ret = self.args_dict['url']
        else:
            ret = '-'
        return (self.__find_header_order('url'), ret)

    def __whitelist(self):
        ret = ''
        if self.args_dict['whitelist'] is not None and len(self.args_dict['whitelist']) > 0:
            ret = self.args_dict['whitelist']
        else:
            ret = '-'
        return (self.__find_header_order('whitelist'), ret)

    def __confidence(self):
        ret = None
        if self.args_dict['cif_confidence'] is not None and len(self.args_dict['cif_confidence']) > 0:
            try:
                t_int = int(self.args_dict['cif_confidence'])
                if isinstance(t_int, (int, long)) and (t_int > 0 and t_int < 100):
                    ret = str(t_int)
            except ValueError:
                ret = None
        return (self.__find_header_order('cif_confidence'), ret)

    def __in_whitelist(self, t):
        ret = False
        if self.args_dict['whitelist'] is not None and len(self.args_dict['whitelist']) > 0:
            if len(re.findall(str.decode(self.args_dict['whitelist']), t)) > 0:
                ret = True
        return ret

    def __file(self):
        ret = None
        if self.args_dict['file'] is not None and len(self.args_dict['file']) > 0 and os.path.exists(self.args_dict['file']):
            ret = open(self.args_dict['file'], 'rb')
        else:
            ret = sys.stdin
        return ret

    def __prep_append_intel_line(self):
        self.append_intel_line = '\t'.join([t[2]()[1] for t in self.sorted_hdr[3:]])

    def __put_header(self):
        ret = ''
        t_args_dict_to_field_name = map(lambda x: x[0], self.option_to_header)
        for k in self.args_dict.keys():
            if self.args_dict[k] is not None:
                try:
                    t_index = t_args_dict_to_field_name.index(k)
                    self.sorted_hdr.append((t_index, self.option_to_header[t_index][1], self.option_to_header[t_index][2]))
                except ValueError:
                    pass

        if len(self.sorted_hdr) > 0:
            self.sorted_hdr.sort(key=lambda x: x[0])
            ret = '\t'.join(map(lambda x: x[1], self.sorted_hdr))
        else:
            error('Failed to generate header')
        sys.stdout.write(ret + "\n")

    def __strip_uri(self, line):
        ret = ''
        parsed = urlparse(line)

        if len(parsed) > 0:
            if parsed.netloc:
                ret += parsed.netloc
            if parsed.path:
                ret += parsed.path
            if parsed.params:
                ret += ";" + parsed.params
            if parsed.query:
                ret += '?' + parsed.query
            if parsed.fragment:
                ret += '#' + parsed.fragment
        return ret

    def __type(self, line):
        ret = self._bitt.determine(line)
        return ret

    def format(self):
        t_fd = self.__file()

        if t_fd is not None:
            self.__put_header()
            self.__prep_append_intel_line()

            for line in t_fd:
                t_line = line.strip()
                if len(t_line) > 0:
                    if self.args_dict['strip_uri']:
                        t_line = self.__strip_uri(t_line)

                    # Special case, we need to generate the indicator_type
                    # based on the input data
                    t_type = self.__type(t_line)

                    print '%s\t%s\t%s' % (t_line, t_type, self.append_intel_line)

            if t_fd is not sys.stdin:
                t_fd.close()


def main():
    parser = OptionParser()
    parser.add_option('-f', dest='file', help='Read parsed list from file (if option is ommited, use stdin)')
    parser.add_option('-g', dest='cif_severity', help="""Reported Severity: 'low', 'medium', 'med', 'high'""")
    parser.add_option('-c', dest='cif_confidence', help="""Confidence percentage - 0...100""")
    parser.add_option('-k', dest='cif_impact', help='meta.cif_impact')
    parser.add_option('-d', dest='desc', help='Description of entry (meta.desc)')
    parser.add_option('-i', dest='if_in', help='Location seen in Bro (def: null)')
    parser.add_option('-n', dest='notice', help="""Call Notice Framework on matches:
                                                   true
                                                   false
                                                   (def: false)""")
    parser.add_option('-S', dest='strip_uri', help='Strip URI(s) if present')
    parser.add_option('-s', dest='source', help='Name for data source (def: mal-dnssearch)')
    parser.add_option('-u', dest='url', help='URL of feed (if applicable)')
    parser.add_option('-w', dest='whitelist', help="""Whitelist pattern (e.g. -w "192\.168", -w "bad|host|evil")""")

    (options, args) = parser.parse_args()

    if len(sys.argv) < 1:
        parser.print_help()
        sys.exit(1)

    args_dict = {}
    for o in options.__dict__.keys():
        args_dict[o] = options.__dict__[o]

    md2b = mal_dns2bro(args_dict)
    md2b.format()

if __name__ == '__main__':
    main()
