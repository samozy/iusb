#!/bin/env python2.7
import socket
import binascii
import time
import sys
import os
import traceback

# TODO: Properly calculate header checksum?


# Base packet dict, unless empty the key's value is static
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

tx_reset = ['00', 'f1'] # Fail

def build_packet(checksum, data_packet_len, sequence, data):
  print " *** SENT:"
  built_packet = binascii.unhexlify(str(packet['hdr_sig'] + packet['major'] + packet['minor'] + packet['packet_header_length'] + checksum \
    + data_packet_len + packet['wtf'] + packet['device_number'] + packet['interface_number'] + packet['data_direction'] + packet['client_data'] + sequence + packet['reserved'] + packet['wtf2'] + data))

  packet_data(built_packet)
  return built_packet 

def build_data_packet(seq_num, req_num, pkt_size, data_packet_command, command, wtf_cmd, more_stupid_shit, data):
  print " *** SENT:"
  built_packet = binascii.unhexlify(str(packet['hdr_sig'] + packet['major'] + packet['minor'] + packet['packet_header_length'] + "00" \
    + ''.join(pkt_size) + packet['wtf'] + packet['device_number'] + packet['interface_number'] + packet['data_direction'] + packet['client_data'] + seq_num + packet['reserved'] + packet['wtf2'] + "00"+ ''.join(data_packet_command) +"0000"+''.join(command)+"00000000"+''.join(wtf_cmd)+"00000000000000"+''.join(more_stupid_shit)+"0000") + data)

  packet_data(built_packet)
  return built_packet

def get_incoming_data(data):
  seq_num = get_seq(data)
  req_num = get_req(data)

  data = binascii.hexlify(data)
  n = 2
  fixed = [data[i:i+n] for i in range(0, len(data), n)]

  packet_data = fixed[36:]

  return seq_num, req_num, packet_data

def get_full_incoming_data_packet(data):
  data = binascii.hexlify(data)
  n = 2
  fixed = [data[i:i+n] for i in range(0, len(data), n)]

  packet_data = fixed[32:]

  return packet_data

def get_seq(data): # Get our Sequence #
  data = binascii.hexlify(data)
  n = 2
  fixed = [data[i:i+n] for i in range(0, len(data), n)]
  return fixed[24]

def get_req(data):
  data = binascii.hexlify(data)
  n = 2
  fixed = [data[i:i+n] for i in range(0, len(data), n)]
  return fixed[36:42]

def get_size(data):
  fixed = str(data[2:3] + data[3:4] + data[0:1] + data[1:2])
  return fixed

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
  print "* DataPacketLen: %s%s" % (fixed[12], fixed[13])
#  print "* ServerCaps: %s" % fixed[13]
#  print "* DeviceType: %s" % fixed[14]
#  print "* Protocol: %s" % fixed[15]
  print "* Direction: %s" % fixed[19] # 00 == to us, 80 == from us
  print "* DeviceNumber: %s" % fixed[17]
  print "* InterfaceNumber: %s" % fixed[18]
  print "* ClientData: %s %s" % (fixed[20], fixed[21])

  print "* SequenceNumber: %s" % fixed[24]
  print "* Reserved: %s %s %s %s" % (fixed[25], fixed[26], fixed[27], fixed[28])
#  print "* DATA (Len = %s bytes): %s" % (len(fixed[29:]), fixed[29:])
  print "* DATA (Len = %s bytes): %s" % (len(fixed[32:]), fixed[32:])
#  print splithex(data)
  print "*---------------------------------------------------------------------------------------"

def splithex(data):
  data = binascii.hexlify(data)
  n = 2
  fixed = [data[i:i+n] for i in range(0, len(data), n)]

  return ' '.join(fixed)

con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = (<HOST>, 5123)
con.setblocking(1)
#con.settimeout(5.0) # If there is no data/activity, this will time out the connection
con.connect(server)
print "[*] Connected..."
print "[*] REC #1"
reply = con.recv(256)
packet_data(reply)
req_num = get_req(reply)
print "FILE REQ# %s" % req_num

time.sleep(2)

counter = 2
seq_num = 0
req_num = 0
cmd = 0
incoming = 0

# Standard initialization/negotiation ping-pong here.
# The main point here is to negotiate disk size
while True:
  reply = con.recv(256)
  print "[*] REC #%s" % counter
  packet_data(reply)
  time.sleep(1)
  incoming = get_incoming_data(reply)

  seq_num = incoming[0]
  req_num = incoming[1][0]
  cmd = incoming[1][4:]
  print "[***] SEQ: %s" % seq_num
  print "[***] REQ: %s" % req_num

  if cmd == ['01', '25']:
#                                                                       THIS is a very important packet, it tells them the SIZE of the disk
#									e.g.: kernel: sd 548:0:0:0: [sdb] 2880 512-byte logical blocks: (1.47 MB/1.40 MiB)
    send_packet = build_packet("00", "2500", seq_num, "08000000"+req_num+"00000001250000000000000000000000000000000800000000000b3f00000200")
    con.send(send_packet)
  elif cmd == ['01', '28']:
    print "GIB us file!"
    print incoming[1]

    break # Ok time for file stuff
  else:
    send_packet = build_packet("00", "1d00", seq_num, "00000000"+''.join(incoming[2]))
    con.send(send_packet)
  if req_num == tx_reset:
    print "We got a reset signal... bye."
    sys.exit(1)
  counter += 1

##
print "******************* Time to transfer the file ********"

file = open('fdboot.img', 'rb')
zero_pos = file.tell()
file.seek(0, os.SEEK_END)
file_size = file.tell()
file.seek(zero_pos, os.SEEK_SET)

print "FILE REQ# %s" % req_num
##

def read1k():
  print "* Read file... Size == %s" % file_size
  return file.read(4096)


# Set up some stuff here
con.settimeout(5.0) # We want to time out if we don't get replies at least the first time
data_sent = 0 # Counter of how much data we've sent
read_size = 4096 # Initially 4096 then drops to 512


while data_sent <= file_size:
  try:
    reply = con.recv(256)
    if reply: print "[***] FILE REC'D:"
    incoming = get_incoming_data(reply)
    packet_data(reply)
    seq_num = incoming[0]
    req_num = incoming[1][0]
    cmd = incoming[1][4:]
    data_packet_command = get_full_incoming_data_packet(reply)
    print "[***] SEQ: %s" % seq_num
    print "[***] REQ: %s" % incoming[1]
    print "[***] CMD: %s" % cmd   
  except:
    pass # Got nothing to recieve
  
  # This is to pass our first wait,need to fix this. Once negotiation goes to file transfer, we have one lapse of recieve
  con.settimeout(None)

  # Start transmiting file data
  if cmd == ['01', '28']:
    wtf_cmd = incoming[2][10:14] # Another kind of command or something, examples: 10 00 00 08, 00 00 00 20, 00 00 00 01, 13 00 00 01, 14 00 00 01 (another counter?)
    data_packet_command = get_full_incoming_data_packet(reply)
    data_packet_size = '10'
    print "WTF: %s" % wtf_cmd
    print incoming
    print data_packet_command

    #if read_size == 512:
    data_packet_size = data_packet_command[:2] #'02' #data_packet_command[26]
    read_size = int(str('0x' + ''.join(data_packet_command[1]) + '00'), 16)

    data_packet_size_send = str('1d' + ''.join(data_packet_size[1])) # Fix this so its not hardcoded
    print data_packet_size
    print data_packet_size_send 

###############
    # This is temprorary, tells us what offset into the file to read into
    binary_read_loc = data_packet_command[14] # 14th byte of reply, not counting the 0x00 before it!
    file.seek(int(binary_read_loc,16))
    print "Location to READ: %s" % int(binary_read_loc, 16)

#the problem is DataPacketLen is not right, fix the data_packet_size_send shit
###############

    piece = file.read(read_size)
    loc = file.tell() # In case we need to know where we are in the file
    print "* Sending Chunk of Size: %s bytes or %s (Actually sending: %s) " % (len(piece), hex(len(piece))[2:], str(get_size(str(hex(len(piece))[2:]))))
    send_packet = build_data_packet(seq_num, "FAKE", data_packet_size_send, data_packet_command[1], incoming[1], wtf_cmd, data_packet_size, binascii.hexlify(piece))
    length = con.send(send_packet)
    data_sent = data_sent + length
    print "Data Sent: %s" % data_sent
    print "Data Piece: %s" % len(piece)
    continue

  # Seems to be ping or keep alive, wants exact same packet in return.
  if cmd == ['01', '1e']:
    send_packet = build_packet("00", "1d00", seq_num, "00000000"+''.join(incoming[2]))
    con.send(send_packet)
    print "oh wtf"
    continue

  # Same as above??
  if cmd == ['01', '00']:
    send_packet = build_packet("00", "1d00", seq_num, "00000000"+''.join(incoming[2]))
    con.send(send_packet)
    print "do something magical"
    continue

  # We are being asked for size update, or re-negotiate?
  if cmd == ['01', '25']:
    send_packet = build_packet("00", "2500", seq_num, "08000000"+req_num+"00000001250000000000000000000000000000000800000000000b3f00000200")
    con.send(send_packet)
    continue

  # This appears to be "drop data packet size" code? Recieved when you try to query the drive from OS
  # 0x200 == 512
  if cmd == ['01', '5a']:
    read_size = 512 # Yeah
    if incoming[2][7] == '1c': # Ugh wtf, need to redo this part
      send_packet = build_packet("00", "1d00", seq_num, "40000000"+req_num+"000000015a001c0000000000400000000105200000000000")
      con.send(send_packet)
      continue
    elif incoming[2][7] == '19':
      send_packet = build_packet("00", "1d00", seq_num, "40000000"+req_num+"000000015a00190000000000400000000105200000000000")
      con.send(send_packet)
      continue
    elif incoming[2][7] == '0a':
      send_packet = build_packet("00", "1d00", seq_num, "40000000"+req_num+"000000015a000a0000000000400000000105200000000000")
      con.send(send_packet)
      continue
    print incoming
    continue

  if req_num == tx_reset:
    print "RESET received, error in transfer."
    sys.exit(1)
  else:
    print "REQ# %s" % req_num

  if data_sent >= file_size:
    raw_input("We're done TX'ing file, now what?")

con.close()
file.close()
print "DID WE GET HERE SOMEHOW?"
time.sleep(30)

sys.exit(0)
