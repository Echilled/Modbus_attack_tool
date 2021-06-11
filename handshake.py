from scapy.all import *
from scapy.layers.inet import TCP, IP

# Defining the script variables
from smod_eugene.System.Core.Modbus import ModbusADU, ModbusPDU01_Read_Coils, ModbusPDU05_Write_Single_Coil

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
    pkt[TCP].flags = 'PA'
    pkt[TCP].seq = seqNr
    pkt[TCP].ack = ackNr
    send(pkt)

# First we establish a connection. The packet returned by the
# function contains the connection parameters
ConnectionPkt = tcpHandshake()

# With the connection packet as a base, create a Modbus
# request packet to read coils
ModbusWritePkt = ConnectionPkt/ModbusADU()/ModbusPDU05_Write_Single_Coil()

# Set the function code, start and stop registers and define
# the Unit ID


ModbusWritePkt[ModbusPDU05_Write_Single_Coil].funcCode = 5
ModbusWritePkt[ModbusPDU05_Write_Single_Coil].unitId = 1
ModbusWritePkt[ModbusPDU05_Write_Single_Coil].outputAddr = 0x6
ModbusWritePkt[ModbusPDU05_Write_Single_Coil].outputValue = 0xff00

# As an example, send the Modbus packet 5 times, updating
# the transaction ID for each iteration
# for i in range(1, 6):
    # Create a unique transaction ID
ModbusWritePkt[ModbusADU].transId = transID + 1 * 3
    # ModbusPkt[ModbusPDU01_Read_Coils].startAddr = random.randint(0, 65535)

    # Send the packet
connectedSend(ModbusWritePkt)

    # Wait for response packets and filter out the Modbus response packet
Results = sniff(count=1, filter='tcp[tcpflags] & (tcp-push|tcp-ack) != 0')
ResponsePkt = Results[0]
updateSeqAndAckNrs(ModbusWritePkt, ResponsePkt)
ResponsePkt.show()
sendAck()

endConnection()
