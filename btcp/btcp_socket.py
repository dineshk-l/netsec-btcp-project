import struct
import logging
from enum import IntEnum


logger = logging.getLogger(__name__)


class BTCPStates(IntEnum):
    """Enum class that helps you implement the bTCP state machine.

    Don't use the integer values of this enum directly. Always refer to them as
    BTCPStates.CLOSED etc.

    These states are NOT exhaustive! We left out at least one state that you
    will need to implement the bTCP state machine correctly. The intention of
    this enum is to give you some idea for states and how simple the
    transitions between them are.

    Feel free to implement your state machine in a different way, without
    using such an enum.
    """
    CLOSED = 0
    ACCEPTING = 1
    SYN_SENT = 2
    SYN_RCVD = 3
    ESTABLISHED = 4  # There's an obvious state that goes here. Give it a name.
    FIN_SENT = 5
    CLOSING = 6
    # __          = 7 # If you need more states, extend the Enum like this.
    # raise NotImplementedError("Check btcp_socket.py's BTCPStates enum. We left out some states you will need.")


class BTCPSignals(IntEnum):
    """Enum class that you can use to signal from the Application thread
    to the Network thread.

    For example, rather than explicitly change state in the Application thread,
    you could put one of these in a variable that the network thread reads the
    next time it ticks, and handles the state change in the network thread.
    """
    ACCEPT = 1
    CONNECT = 2
    SHUTDOWN = 3


class BTCPSocket:
    """Base class for bTCP client and server sockets. Contains static helper
    methods that will definitely be useful for both sending and receiving side.
    """

    def __init__(self, window, timeout):
        logger.debug("__init__ called")
        self._window = window
        self._timeout = timeout
        self._state = BTCPStates.CLOSED
        logger.debug("Socket initialized with window %i and timeout %i",
                     self._window, self._timeout)

    @staticmethod
    def in_cksum(segment):
        """Compute the internet checksum of the segment given as argument.
        Consult lecture 3 for details.

        Our bTCP implementation always has an even number of bytes in a segment.

        Remember that, when computing the checksum value before *sending* the
        segment, the checksum field in the header should be set to 0x0000, and
        then the resulting checksum should be put in its place.
        """
        # assumes even number of bytes
        # checksum to verify the integrity of the segments (part of reliability) and for incremental passing of the next test case in the framework with "spurious bit flips"
        # A segment with invalid checksum should be ignored. this verification should be taken care of by the function(s) thats going to use the checksum - eg lossy_layer_segment_received()
        logger.debug("in_cksum() called")
        logger.info("Psueudo header including IP not taken into account")

        # # If the segment length is odd, pad it with a zero byte (but we ignore this because it was made even for us)
        # if len(segment) % 2 == 1:
        #     segment += b'\x00'

        # Calculate the sum of all 16-bit words in the segment
        total = 0
        for i in range(0, len(segment), 2):
            # each byte object is 8 bits
            # to get a 16 bit (2 byte) representation of their addition
            total += (segment[i] << 8) + segment[i+1]

        # Fold the carry bits into the sum
        while (total >> 16) > 0:
            # the first step is to isolate the 16 MSB and add the carry bits to them. if its still overflows, continue the process
            total = (total & 0xFFFF) + (total >> 16)

        # Take the one's complement of the sum
        checksum = ~total & 0xFFFF

        # Pack the checksum into a 2-byte binary string in network byte order
        packed_checksum = struct.pack('!H', checksum)

        logger.debug(
            "in_checsum() finished. Checksum calculated: ", packed_checksum)

        return packed_checksum
        # raise NotImplementedError(
        #     "No implementation of in_cksum present. Read the comments & code of btcp_socket.py.")

    @staticmethod
    def verify_checksum(segment):
        """Verify that the checksum indicates is an uncorrupted segment.

        Mind that you change *what* signals that to the correct value(s).
        """
        logger.debug("verify_cksum() called")
        # save checksum received into temporary variable
        checksum_to_verify = segment[8:10]
        # set checksum field to 0x0000 to prepare for its recomputation
        segment_checksum_zeroed = segment[:8] + \
            struct.pack("!H", 0x0000) + segment[10:]
        # recompute checksum
        checksum_recomputed = BTCPSocket.in_cksum(
            segment_checksum_zeroed)  # returns packed
        # raise NotImplementedError(
        #     "No implementation of in_cksum present. Read the comments & code of btcp_socket.py.")
        return checksum_recomputed == checksum_to_verify

    @staticmethod
    def build_segment_header(seqnum, acknum,
                             syn_set=False, ack_set=False, fin_set=False,
                             window=0x01, length=0, checksum=0):
        """Pack the method arguments into a valid bTCP header using struct.pack

        This method is given because historically students had a lot of trouble
        figuring out how to pack and unpack values into / out of the header.
        We have *not* provided an implementation of the corresponding unpack
        method (see below), so inspect the code, look at the documentation for
        struct.pack, and figure out what this does, so you can implement the
        unpack method yourself.

        Of course, you are free to implement it differently, as long as you
        do so correctly *and respect the network byte order*.

        You are allowed to change the SYN, ACK, and FIN flag locations in the
        flags byte, but make sure to do so correctly everywhere you pack and
        unpack them.

        The method is written to have sane defaults for the arguments, so
        you don't have to always set all flags explicitly true/false, or give
        a checksum of 0 when creating the header for checksum computation.
        """
        logger.debug("build_segment_header() called")
        flag_byte = syn_set << 2 | ack_set << 1 | fin_set
        logger.debug("build_segment_header() done")
        return struct.pack("!HHBBHH",
                           seqnum, acknum, flag_byte, window, length, checksum)

    @staticmethod
    def unpack_segment_header(header):
        """Unpack the individual bTCP header field values from the header.

        Remember that Python supports multiple return values through automatic
        tupling, so it's easy to simply return all of them in one go rather
        than make a separate method for every individual field.
        """
        logger.debug("unpack_segment_header() called")
        # where 'unpacked' is (seqnum, acknum, flag_byte, window, length, checksum)
        unpacked = struct.unpack("!HHBBHH", header)
        # raise NotImplementedError( "No implementation of unpack_segment_header present. Read the comments & code of btcp_socket.py. You should really implement the packing / unpacking of the header into field values before doing anything else!")
        logger.debug("unpack_segment_header() done")
        # (seqnum, acknum, flag_byte, window, length, checksum)
        return unpacked
