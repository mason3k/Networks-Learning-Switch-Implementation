'''
Ethernet learning switch in Python.
'''
from switchyard.lib.userlib import *

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

    Interface object:
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
    learning_table = SwitchTable(5)

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
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
    curRow = 0
    learningTable = []
    limit = 0

    '''
    initialize a learning switch table where
    limit is the number of entries before we purge
    '''
    def __init__(self,limit):
        self.limit = limit
        self.curRow = 0
        self.learningTable=[]
        for i in range(limit):
            self.learningTable.append(["00:00:00:00:00:00",None])

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




        





