#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2013 Bryan Davis and Wikimedia Foundation. All Rights Reserved.
"""
Listen for HTCP cache purge datagrams.

:author: Bryan Davis <bd808@wikimedia.org>
"""

import logging
import socket
import struct

def hexdump(src, length=16, sep='.'):
    """Display a string as a hexdump.

    From: https://gist.github.com/7h3rAm/5603718
    """
    FILTER = ''.join([
        (len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)
        ])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        if len(hex) > 24:
            hex = "%s %s" % (hex[:24], hex[24:])
        printable = ''.join([
            "%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars
            ])
        lines.append("%08x: %-*s |%s|\n" % (c, length*3, hex, printable))
    print ''.join(lines)

class Server (object):

    def __init__ (self):
        """
        Constructor.
        """
        self.log = logging.getLogger(self.__class__.__name__)
        self.max_dgram_size = 65507
    #end __init__

    def handle_message (self, payload):
        """
        Handle a message received from a client.
        """
        self.log.debug("handle: %s", payload)
        print hexdump(payload)

        # TODO: decode HTPC packet
        # »···»···»···$htcpSpecifier = pack( 'na4na*na8n',
        # »···»···»···»···4, 'HEAD', strlen( $url ), $url,
        # »···»···»···»···8, 'HTTP/1.0', 0 );
        #
        # »···»···»···$htcpDataLen = 8 + 2 + strlen( $htcpSpecifier );
        # »···»···»···$htcpLen = 4 + $htcpDataLen + 2;
        #
        # »···»···»···// Note! Squid gets the bit order of the first
        # »···»···»···// word wrong, wrt the RFC. Apparently no other
        # »···»···»···// implementation exists, so adapt to Squid
        # »···»···»···$htcpPacket = pack( 'nxxnCxNxxa*n',
        # »···»···»···»···$htcpLen, $htcpDataLen, $htcpOpCLR,
        # »···»···»···»···$htcpTransID, $htcpSpecifier, 2 );
        #                   ' nxx nCx Nxxa* n'
        #pkt = struct.unpack('>Hxx>HBx>Lxx*s>H', payload)
        # payload is:
        # [header][data]([auth]*)
        # header := 32bit len, 8bit major ver, 8bit minor ver
        # data := 16bit len, 4bit opcode, 4bit response, 6bit reserved,
        #         1bit 
    #end handle_message

    def _keep_running (self):
        return self._sock is not None
    #end _keep_running

    def serve (self, hostname='', port=4827):
        """
        Listen for UDP datagrams sent to the given host and port.
        Process each datagram as it arrives.

        :param hostname: Hostname or ipv4 dotted quad address
        :type hostname: string
        :param port: UDP port number
        :type port: int
        """
        self.log.info("Starting server on %s:%d", hostname, port)
        self._sock = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self._sock.bind((hostname, port))

        # trap some os signals
        import signal
        def stop_on_signal (signal, frame):
            self.log.warning("Received signal %d", signal)
            self.stop()
        #end stop_on_signal
        signal.signal(signal.SIGINT, stop_on_signal)
        signal.signal(signal.SIGHUP, stop_on_signal)
        signal.signal(signal.SIGTERM, stop_on_signal)

        while self._keep_running():
            try:
                self.log.debug("waiting for dgram")
                payload, addr = self._sock.recvfrom(self.max_dgram_size)
                self.log.info("dgram from %s", addr)
                self.handle_message(payload)

            except (KeyboardInterrupt, SystemExit), e:
                self.log.warning("Exiting: %s", e)
                raise

            except Exception, e:
                self.log.exception("Error serving: %s ", e)
        #end while
    #end serve

    def stop (self):
        self.log.warning("shutting down")
        self._sock.close()
        self._sock = None
    #end stop
#end class Server


if __name__ == '__main__':
    # TODO params:
    # port
    # host
    # verbose (multiple): 1 = INFO, 2 = DEBUG

    # setup logger
    import sys
    logging.basicConfig(
            stream=sys.stderr,
            level=logging.DEBUG,
            format='%(asctime)s %(levelname)s - %(message)s')

    # run server
    server = Server()
    server.serve()

# vim:set sw=4 ts=4 sts=4 et:
