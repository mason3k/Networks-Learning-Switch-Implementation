#cky: learning github

#cky: merge test 2

#suj test

#this better work

'''
Ethernet learning switch in Python.
Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *

'''
main Entrypoint
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
        #TODO: record interface of source address (packet[0].src -> input_port) ? in table
        #if it is not already in there
        source_address = packet[0].src 
        destination_address = packet[0].dst

        if learning_table.isAddressAlreadyMapped(source_address)==False:
            learning_table.addRow(source_address,input_port)

        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        
        #TODO if it is not the "all interfaces message" and we know where we should be going based 
        #on the table (i.e., destination in table), send it straight there
        elif destination_address.upper() != "FF:FF:FF:FF:FF:FF" and learning_table.isAddressAlreadyMapped(destination_address):
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
    '''
    add a row to learning switch table
    '''
    def addRow(address,port):
        if SwitchTable.curRow > 4:
            SwitchTable.curRow = 0

        SwitchTable.learningTable[curRow] = [address , port]
        SwitchTable.curRow += 1
        return

    '''
    Helper function to check if the address is already in the table
    '''
    def isAddressAlreadyMapped(address):
        for row in SwitchTable.learningTable:
            if row[0] == address:
                return True

        return False

    '''
    Return the port we have mapped for the address
    '''
    def getMappedPort(address):
        for row in SwitchTable.learningTable:
            if row[0] == address:
                return row[1]

        return ""


        





