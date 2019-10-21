import struct
from switchyard.lib.userlib import *
import datetime


'''
main Entrypoint

Variables:
net: switchyard network object
    methods:
        interfaces() or ports() - 
            return value: list of Interface objects that are configured on the network device
        recv_packet(timeout = none) - receive at most one packet from any port.  block until a packet is received or timeout (optionally passed in) has passed
            retrun value: namedtuple of lenght 3 - timestamp for when the packet was received, name of the input port on which the packet was received, packet itself
                recvdata = net.recv_packet()
                recvdata.timestamp, recvdata.packet, recvdata.input_port or recvdata[0], recvdata[1], recvdata[2]
        send_packet(output_port, packet) - send a packet to output_port
            output_port: string name of the port or Interface object
            return value: none

    Interface (port) object:
        name: name of the interface (string)
        ethaddr: Ethernet address for the interface
        ipaddr: IPv4 address for the interface.  return value is IPv4Address object.  If no address, address is 0.0.0.0.
        netmask: network mas associated with the IPv4 address for the interface.  Default is 255.255.255.255 (/32)
        ifnum: integer index associated with the interface
        iftype: type of the interface.  Either Unknown, Loopback, Wired, or Wireless (enum in switchyard.lib.interface.InterfaceType)
        All the above except ifnum and iftype can be modified.

        for  more info: https://jsommers.github.io/switchyard/writing_a_program.html

Packet object:
    container of headers (header object)
    packet[0] or pakcet[Ethernet], where Ethernet is the packet header class name: lowest layer header - most likely Ethernet header
        packet[1] = IPv4
        packet[2] = ICMP
    packet[0].src: packet Ethernet header source address
    packet[0].dst: packet Ethernet header destination address
    packet[0].ethertype: packet Ethernet header type


my_interfaces: list of ports (or interfaces)
mymacs: list of interface Ethernet headers
timestamp: timestamp of when the packet was received in the input port
input_port: port name where the packet was received
packet: packet object received
'''
def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    #TODO Get lowest address in mymacs (ethAddr objects have a built-in compare opertor so can just use </sort method)
    #TODO pass in lowest address from above into SwitchTable as second argument
    learning_table = SwitchTable(5)

    #Flood all interfaces on start-up
    for intf in my_interfaces:
        net.send_packet(intf.name, learning_table.makeSTPPacket() )

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet.has_header(SpanningTreeMessage):
            spanning_header = packet.get_header(SpanningTreeMessage)
            #TODO Call learningTable.updateFromSTP(spanning_header,input_port) to update switch with packet info
            #TODO forward to everyone except the source (or everyone if we're the root)

            #Don't want to learn from this, so break out of loop here
            continue


        log_debug ("Learning: In {} received packet {} on {}".format(net.name, packet, input_port))
        #Record interface of source address (packet[0].src -> input_port) in table
        #if it is not already in there
        source_address = packet[0].src 
        destination_address = packet[0].dst

        if learning_table.isAddressAlreadyMapped(source_address)==False:
            learning_table.addRow(source_address,input_port)

        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
            
        
        
        #If it is not the "all interfaces message" and we know where we should be going based 
        #on the table (i.e., destination in table), send it straight there
        elif destination_address != "FF:FF:FF:FF:FF:FF" and learning_table.isAddressAlreadyMapped(destination_address):
            destination_port = learning_table.getMappedPort(destination_address)
            log_debug("Mapped destination found: {}".format(destination_port))
            net.send_packet(destination_port, packet)
       
        else:
            for intf in my_interfaces:
                #We don't want to send it back where it came from
                #TODO update to handle blocked ports
                if input_port != intf.name:
                    log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                    net.send_packet(intf.name, packet)
    net.shutdown()


'''
A class defining the learning table

SwitchTable format:
curRow: pointer to the row we are current pointing at in learningTable
limit: max number of rows we can have in learningTable
learningTable: double list of [address, port] combinations
    ex) learningTable = [ [addr1, port1], [addr2, port2], [addr3, port3], [addr4, port4], [addr5, port5] ]
        if curRow is 3, we are pointing at [addr4, port4] in learningTable
'''
class SwitchTable:

    '''
    initialize a learning switch table where
    limit is the number of entries before we purge
    '''
    def __init__(self,limit,myId=None):
        self.limit = limit
        self.curRow = 0
        self.learningTable=[]
        for i in range(limit):
            self.learningTable.append(["00:00:00:00:00:00",None])
        self.myId = id
        self.rootId = id
        self.hopsToRoot = 0
        self.timeSpanPackLastRecvd = None
        self.blockedInterfaces = []
        #rootInterface = the interface we're getting current root packets from
        self.rootInterface = None

    '''
    add a row to learning switch table
    '''
    def addRow(self,address,port):
        if self.curRow > 4:
            self.curRow = 0
        
        self.learningTable[self.curRow] = [address , port]
        self.curRow += 1
        return

    '''
    Helper function to check if the address is already in the table
    '''
    def isAddressAlreadyMapped(self,address):
        for row in self.learningTable:
            if row[0] == address:
                return True

        return False

    '''
    Return the port we have mapped for the address
    '''
    def getMappedPort(self,address):
        for row in self.learningTable:
            if row[0] == address:
                return row[1]

        return ""
    '''
    For use in testing
    '''
    def writeTable(self):
        for row in self.learningTable:
            print(row[0] + " " + row[1])
        return

    '''
    Send an STP Packet based on current switch information
    '''
    def makeSTPPacket(self)
         spt_header = SpanningTreeMessage(self.rootId,self.hopsToRoot,self.myId)
        
        Ethernet.add_next_header_class(EtherType.SLOW, SpanningTreeMessage)
        pkt = Ethernet(src="00:00:00:00:00:00", dst="FF:FF:FF:FF:FF:FF",ethertype=EtherType.SLOW) + spt_header
        
        xbytes = pkt.to_bytes()
        p = Packet(raw=xbytes)
        return p

    '''
    Returns True if current switch is root
    Returns False if current switch is not root
    '''
    def iAmRoot(self)
        return self.myId == self.rootId

    '''
    Call this when we receive an STP packet to update the switch with new information
    '''
    def updateFromSTP(self,STP_header,input_port)
        #Calling this when receiving an update, so set last recieved time to now
        self.timeSpanPackLastRcvd = datetime.datetime.now()

        if (STP_header.root < self.root) or (self.rootInterface != None and (self.rootInterface == input_port)):
            #TODO update root info
            #TODO send packet per updated info

        if (STP_header.root > self.root):
            #TODO don't know if the above conditional is right
            #Delete input_port from self.blockedInterfaces

        if  (STP_header.root == self.root):
            #TODO update hops
            #TODO block input_port if appropriate
      


#this class will have all the methods and variables.  Also udpate main to
# 1. create a spanning tree packet. look at the test script
# 2. send this packet periodically (only root node generates this)
# 3. update (root node, block, and etc...) as necesary
# id of a switch is the lowest MAC address of all the ports this switch has
# 
class SpanningTreeMessage(PacketHeaderBase):
    _PACKFMT = "6sxB6s"

    # switch_id is the id of the switch that forwarded the stp packet
    # in case the stp packet is generated ensure switch_id=root_id

    def __init__(self, root_id="00:00:00:00:00:00", hops_to_root=0, switch_id="00:00:00:00:00:00", **kwargs):
        self._root = EthAddr(root_id)
        self._hops_to_root = hops_to_root
        self._switch_id = EthAddr(switch_id)
        PacketHeaderBase.__init__(self, **kwargs)
        
        


    def to_bytes(self):
        raw = struct.pack(self._PACKFMT, self._root.raw, self._hops_to_root, self._switch_id.raw)
        return raw

    def from_bytes(self, raw):
        packsize = struct.calcsize(self._PACKFMT)
        if len(raw) < packsize:
            raise ValueError("Not enough bytes to unpack SpanningTreeMessage")
        xroot,xhops, xswitch = struct.unpack(self._PACKFMT, raw[:packsize])
        self._root = EthAddr(xroot)
        self.hops_to_root = xhops
        self._switch_id = EthAddr(xswitch)
        return raw[packsize:]

    @property
    def hops_to_root(self):
        return self._hops_to_root

    @hops_to_root.setter
    def hops_to_root(self, value):
        self._hops_to_root = int(value)

    @property
    def switch_id(self):
        return self._switch_id

    @switch_id.setter
    def switch_id(self, switch_id):
        self._switch_id = switch_id

    @property
    def root(self):
        return self._root

    def __str__(self):
        return "{} (root: {}, hops-to-root: {}, switch_id: {})".format(
            self.__class__.__name__, self.root, self.hops_to_root, self.switch_id)