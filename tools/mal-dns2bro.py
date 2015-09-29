#!/usr/bin/python
#
# Aaron Eppert
# September 2015
#
# September 28, 2015        Initial Release                             Aaron Eppert
# September 29, 2015        Dynamic header creation and field filling   Aaron Eppert
#
import os
import re
import sys
import string

from optparse import OptionParser, OptionGroup
from optparse import HelpFormatter as fmt


def decorate(fn):
    def wrapped(self=None, desc=""):
        print 'here'
        return '\n'.join([fn(self, s).rstrip() for s in desc.split('\n')])
    return wrapped
fmt.format_description = decorate(fmt.format_description)


class mal_dns2bro:
    def __init__(self, args_dict):
        self.args_dict = args_dict
        self.append_intel_line = None
        self.sorted_hdr = [(0, '#fields',   None),
                           (1, 'indicator', None)]

        self.s2l_types = {'ip':        'Intel::ADDR',
                          'domain':    'Intel::DOMAIN',
                          'url':       'Intel::URL',
                          'software':  'Intel::SOFTWARE',
                          'e-mail':    'Intel::EMAIL',
                          'user':      'Intel::USER_NAME',
                          'filehash':  'Intel::FILE_HASH',
                          'filename':  'Intel::FILE_NAME',
                          'certhash':  'Intel::CERT_HASH'}

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

        self.option_to_header = [('#fields',         '#fields',             lambda : None),
                                 ('indicator',       'indicator',           lambda : None),
                                 ('type',            'indicator_type',      self.__type),
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
            print 'ERROR: Invalid header!'
            sys.exit(1)
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

    def __type(self):
        ret = ''
        if self.args_dict['type'] is not None:
            if self.args_dict['type'] in self.s2l_types.keys():
                ret = self.s2l_types[self.args_dict['type']]
            elif self.args_dict['type'] in self.s2l_types.values():
                ret = self.args_dict['type']
            else:
                sys.stderr.write('ERROR: TYPE not specified!\n')
                sys.exit(1)
        return (self.__find_header_order('type'), ret)

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
        self.append_intel_line = '\t'.join([t[2]()[1] for t in self.sorted_hdr[2:]])

    def __gen_header(self):
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
            sys.stderr.write('ERROR: Failed to generate header')
            sys.exit(1)
        return ret

    def format(self):
        t_fd = self.__file()
        if t_fd is not None:
            print self.__gen_header()
            self.__prep_append_intel_line()

            for line in t_fd:
                t_line = line.strip()
                if len(t_line) > 0:
                    print '%s\t%s' % (t_line, self.append_intel_line)

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
    parser.add_option('-T', dest='type', help="""Intel::Type value or short name:
                                            Intel::ADDR\t\t->\tip
                                            Intel::DOMAIN\t->\tdns
                                            Intel::URL\t\t->\turl
                                            Intel::SOFTWARE\t->\tsoftware
                                            Intel::EMAIL\t->\te-mail
                                            Intel::USER_NAME\t->\tuser
                                            Intel::FILE_HASH\t->\tfilehash
                                            Intel::FILE_NAME\t->\tfilename
                                            Intel::CERT_HASH\t->\tcerthash""")
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
