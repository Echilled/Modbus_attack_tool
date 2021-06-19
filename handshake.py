from scapy.all import *
from scapy.layers.inet import TCP, IP
from scapy.fields import XByteField, XShortField, StrLenField, ByteEnumField, \
    BitFieldLenField, ByteField, ConditionalField, EnumField, FieldListField, \
    ShortField, StrFixedLenField, XShortEnumField
# Defining the script variables
from smod_eugene.System.Core.Modbus import ModbusADU, ModbusPDU01_Read_Coils, ModbusPDU05_Write_Single_Coil, \
    ModbusPDU02_Read_Discrete_Inputs
import scapy.contrib.modbus as mb

srcIP = '192.168.110.1'
srcPort = random.randint(1024, 65535)
dstIP = '192.168.110.128'
dstPort = 502
seqNr = random.randint(444, 8765432)
ackNr = 0
transID = random.randint(44, 44444)


def updateSeqAndAckNrs(sendPkt, recvdPkt):
    # Keeping track of tcp sequence and acknowledge numbers
    global seqNr
    global ackNr
    seqNr = seqNr + len(sendPkt[TCP].payload)
    ackNr = ackNr + len(recvdPkt[TCP].payload)


def sendAck():
    # Create the acknowledge packet
    ip = IP(src=srcIP, dst=dstIP)
    ACK = TCP(sport=srcPort, dport=dstPort, flags='A',
                  seq=seqNr, ack=ackNr)
    pktACK = ip / ACK

    # Send acknowledge packet
    send(pktACK)

def tcpHandshake():
    # Establish a connection with the server by means of the tcp
    # three-way handshake
    # Note: linux might send an RST for forged SYN packets.Disable it by executing:
    # > iptables -A OUTPUT -p tcp --tcp-flags RST RST -s <src_ip> -j DROP
    global seqNr
    global ackNr

    # Create SYN packet
    ip = IP(src=srcIP, dst=dstIP)
    SYN = TCP(sport=srcPort, dport=dstPort, flags='S',
                  seq=seqNr, ack=ackNr)
    pktSYN = ip / SYN

    # send SYN packet and receive SYN/ACK packet
    pktSYNACK = sr1(pktSYN)

    # Create the ACK packet
    ackNr = pktSYNACK.seq + 1
    seqNr = seqNr + 1
    ACK = TCP(sport=srcPort, dport=dstPort, flags='A', seq=seqNr, ack=ackNr)
    send(ip / ACK)
    return ip/ACK


def endConnection():
    # Create the rst packet
    ip = IP(src=srcIP, dst=dstIP)
    RST = TCP(sport=srcPort, dport=dstPort, flags='RA',
              seq=seqNr, ack=ackNr)
    pktRST = ip / RST

    # Send acknowledge packet
    send(pktRST)


def connectedSend(pkt):
    # Update packet's sequence and acknowledge numbers
    # before sending
    pkt[TCP].flags = 'PA'  # setting up the packet that basically would be accepted by the slave
    pkt[TCP].seq = seqNr
    pkt[TCP].ack = ackNr
    send(pkt)


def write_coil(ConnectionPkt):
    ModbusWritePkt = ConnectionPkt / ModbusADU() / ModbusPDU05_Write_Single_Coil() # stacking layers for modbus
    ModbusWritePkt[ModbusADU].unitId = 1
    ModbusWritePkt[ModbusPDU05_Write_Single_Coil].funcCode = 5
    ModbusWritePkt[ModbusADU].transId = transID + 1 * 3
    return ModbusWritePkt


def read_coils(ConnectionPkt):
    ModbusReadPkt = ConnectionPkt / ModbusADU() / ModbusPDU02_Read_Discrete_Inputs()  # stacking layers for modbus
    ModbusReadPkt[ModbusADU].unitId = 1
    ModbusReadPkt[ModbusPDU02_Read_Discrete_Inputs].quantity = 1
    ModbusReadPkt[ModbusADU].transId = transID + 1 * 3 + 3
    ModbusReadPkt[ModbusPDU02_Read_Discrete_Inputs].funcCode = 2
    return ModbusReadPkt


def main():
    ConnectionPkt = tcpHandshake() # Establish three way handshake with the slave first
    print("connected")
    while True:
        action = input("User action: 1 for read coils, 2 for write coil, 3 to exit:")
        if action == "1":
            read_packet = read_coils(ConnectionPkt)
            start_addr = input("Coil to read")
            read_packet[ModbusPDU02_Read_Discrete_Inputs].startAddr = int(start_addr)
            connectedSend(read_packet)
            # read_results = sniff(count=2, filter='tcp src port 502',
            #                     iface="VMware Virtual Ethernet Adapter for VMnet1")
            Results = sniff(count=1, filter='tcp[tcpflags] & (tcp-push|tcp-ack) != 0',
                            iface="VMware Virtual Ethernet Adapter for VMnet1")
            ResponsePkt = Results[0]
            updateSeqAndAckNrs(read_packet, ResponsePkt)
            sendAck()
            data = ResponsePkt[Raw].load
            print(data)

        if action == "2":
            write_packet = write_coil(ConnectionPkt)
            Output_addr = input("Enter coil number:")
            write_packet[ModbusPDU05_Write_Single_Coil].outputAddr = int(Output_addr) - 1
            status = input("Turn on or off:")
            if status == "on":
                write_packet[ModbusPDU05_Write_Single_Coil].outputValue = 0xff00
            elif status == "off":
                write_packet[ModbusPDU05_Write_Single_Coil].outputValue = 0x00
            connectedSend(write_packet)

            Results = sniff(count=1, filter='tcp[tcpflags] & (tcp-push|tcp-ack) != 0',
                            iface="VMware Virtual Ethernet Adapter for VMnet1")
            ResponsePkt = Results[0]
            updateSeqAndAckNrs(write_packet, ResponsePkt)

            sendAck()
        elif action == "3":
            endConnection()
            break

        # With the connection packet as a base, create a Modbus
        # request packet to write coils

        # Set the function code, start and stop registers and define
        # the Unit ID
            # Wait for response packets and filter out the Modbus response packet
        # Results = sniff(count=1, filter='tcp[tcpflags] & (tcp-push|tcp-ack) != 0',
        #                 iface="VMware Virtual Ethernet Adapter for VMnet1")
        # # Results = sniff(count=1, filter="tcp port 502")
        # # for packet in Results:
        # #     print(packet.show())
        # ResponsePkt = Results[0]
        # updateSeqAndAckNrs(write_coil(ConnectionPkt), ResponsePkt)
        #
        # ResponsePkt.show()
        # sendAck()

        # endConnection()


if __name__ == "__main__":
    main()
