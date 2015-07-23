#!/bin/env python2.7
import socket
import binascii
import time
import sys

# Base packet dict, unless empty the key's value is static (for the most part...)
packet = {
  'hdr_sig':"4955534220202020",
  'major':"01",
  'minor':"00",
  'packet_header_length':"20",
  'checksum':"00",
  'data_packet_length':"0000",
  'wtf':"000000",
  'device_number':"80",
  'interface_number':"01",
  'data_direction':"80",
  'client_data':"02000000",
  'sequence_number':"00",
  'reserved':"00000000",
  'wtf2':"000000",
  'data':""
}

def build_packet(checksum, data_packet_len, sequence, data):
  print " *** SENT:"
  built_packet = binascii.unhexlify(str(packet['hdr_sig'] + packet['major'] + packet['minor'] + packet['packet_header_length'] + checksum \
    + data_packet_len + packet['wtf'] + packet['device_number'] + packet['interface_number'] + packet['data_direction'] + packet['client_data'] + sequence + packet['reserved'] + packet['wtf2'] + data))

  #print "*** UR PKT: %s" %  binascii.hexlify(built_packet)
  return built_packet

def get_seq(data): # Get our Sequence #
  data = binascii.hexlify(data)
  n = 2
  fixed = [data[i:i+n] for i in range(0, len(data), n)]
  return fixed[24]

def packet_data(data):
  data = binascii.hexlify(data)
  n = 2
  fixed = [data[i:i+n] for i in range(0, len(data), n)]
  # Lets print out our header
  print "*---------------------------------------------------------------------------------------"
  print "* Signature: %s (\"%s\")" % (fixed[:7], binascii.unhexlify(''.join(fixed[:7])))
  print "* Major: 0x%s" % fixed[8]
  print "* Minor: 0x%s" % fixed[9]
  print "* PacketHeaderLen: 0x%s, %s bytes (Actual? %s)" % (fixed[10], int(fixed[10], 16), len(data))
  print "* HeaderChecksum: 0x%s" % fixed[11]
  print "* DataPacketLen: %s" % fixed[12]
#  print "* ServerCaps: %s" % fixed[13]
#  print "* DeviceType: %s" % fixed[14]
#  print "* Protocol: %s" % fixed[15]
  print "* Direction: %s" % fixed[19] # 00 == to us, 80 == from us
  print "* DeviceNumber: %s" % fixed[17]
  print "* InterfaceNumber: %s" % fixed[18]
  print "* ClientData: %s %s" % (fixed[20], fixed[21])

  print "* SequenceNumber: %s" % fixed[24]
  print "* Reserved: %s %s %s %s" % (fixed[25], fixed[26], fixed[27], fixed[28])
  print "* DATA (Len = %s bytes): %s" % (len(fixed[29:]), fixed[29:])
  print splithex(reply)
  print "*---------------------------------------------------------------------------------------"

def splithex(data):
  data = binascii.hexlify(data)
  n = 2
  fixed = [data[i:i+n] for i in range(0, len(data), n)]

  return ' '.join(fixed)

con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = ('<HOST>', 5123)
con.setblocking(1)
#con.settimeout(5.0) # If there is no data/activity, this will time out the connection
con.connect(server)
print "[*] Connected..."
print "[*] REC #1"
reply = con.recv(256)
packet_data(reply)

time.sleep(2)
print "[*] REC #2"
reply = con.recv(256)
packet_data(reply)
time.sleep(1)

seq_num = get_seq(reply)
print "*** SEQ %s" % seq_num

# First TX packet...
send_packet = build_packet("00", "1d00", seq_num, "0000000002000000010000000000000000000000000106280000000000")
con.send(send_packet)

print " "
print ("Listening for data... Press CTRL+C to exit...")
counter = 3 # Starting on 3rd packet
while True:
  try:
    # Lets try a good known packet:
    reply = con.recv(256)
    if not reply:
      break
    else:
      print "[***] REC'D #%s:" % counter
      packet_data(reply)

      seq_num = get_seq(reply)
      print "*** SEQ %s" % seq_num

      send_packet = build_packet("00", "1d00", seq_num, "0000000004000000010000000000000000000000000000000000000000")
      #send_packet = build_packet("0100207b1d0000000080018002000000"+seq_num+"000000000000000000000004000000010000000000000000000000000000000000000000")
      con.send(send_packet)
      counter += 1

  except KeyboardInterrupt:
    break

con.close()
sys.exit(0)
