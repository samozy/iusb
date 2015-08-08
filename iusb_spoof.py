#!/bin/env python2.7
# Author: Stan Ayzenberg
# Copyright (c) 2015, Stan Ayzenberg

# Version: 2.1 (08/07/15)

import socket
import binascii
import time
import sys
import os
import traceback

# Base packet dict, unless empty the key's value is static
iusb_packet = {
  'hdr_sig':"4955534220202020",
  'major':"01",
  'minor':"00",
  'packet_header_length':"20",
  'checksum':"00", # The checksum doesn't appear to be checked at all...
  'data_packet_length':"0000",
  'wtf':"000000",
  'device_number':"80",
  'interface_number':"01",
  'data_direction':"80", # 00 == Rx, 80 == Tx
  'client_data':"02000000",
  'sequence_number':"00",
  'reserved':"00000000",
  'wtf2':"000000",
  'data':""
}

hostname = 'waffle' 
verbose = 0 # Change this to see a lot of junk


def build_packet(checksum, data_packet_len, sequence, data):
  built_packet = binascii.unhexlify(str(iusb_packet['hdr_sig'] + iusb_packet['major'] + iusb_packet['minor'] + iusb_packet['packet_header_length'] + checksum \
    + data_packet_len + iusb_packet['wtf'] + iusb_packet['device_number'] + iusb_packet['interface_number'] + iusb_packet['data_direction'] + iusb_packet['client_data'] + sequence + iusb_packet['reserved'] + iusb_packet['wtf2'] + data))

  if verbose:
    print " *** SENT:"
    packet_data(built_packet)

  return built_packet 

def build_data_packet(seq_num, req_num, pkt_size, data_packet_command, command, wtf_cmd, more_stupid_shit, data):
  built_packet = binascii.unhexlify(str(iusb_packet['hdr_sig'] + iusb_packet['major'] + iusb_packet['minor'] + iusb_packet['packet_header_length'] + "00" \
    + ''.join(pkt_size) + iusb_packet['wtf'] + iusb_packet['device_number'] + iusb_packet['interface_number'] + iusb_packet['data_direction'] + iusb_packet['client_data'] + seq_num + iusb_packet['reserved'] + iusb_packet['wtf2'] + "00"+ ''.join(data_packet_command) +"0000"+''.join(command)+"00000000"+''.join(wtf_cmd)+"00000000000000"+''.join(more_stupid_shit)+"0000") + data)

  if verbose:
    print " *** SENT:"
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
  print "* IUSB Packet"
  print "* ------------"
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

  # Fix this later to not show data packet if it is SCSI, use below
  print "* DATA (Len = %s bytes): %s" % (len(fixed[32:]), fixed[32:])
  print "*---------------------------------------------------------------------------------------"

def scsi_packet_data(data):
  n = 2
  fixed = [data[i:i+n] for i in range(0, len(data), n)]

  print "*---------------------------------------------------------------------------------------"
  print "* SCSI Packet"
  print "* ------------"
  print "* Data Requested Size: 0x%s%s" % (fixed[0],fixed[1]) 
  print "* Data Filler: 0x%s%s" % (fixed[2], fixed[3])
  print "* Data Packet Sequence# %s: " % fixed[4]
  print "* Data Packet Filler: 0x%s%s%s: " % (fixed[5], fixed[6], fixed[7])
  print "* SCSI Command: %s" % fixed[9]
  print "* SCSI Payload: %s %s %s %s %s %s %s %s %s" % (fixed[10], fixed[11], fixed[12], fixed[13], fixed[14], fixed[15], fixed[16], fixed[17], fixed[18])
  print "* Data Filler: 0x%s %s %s %s %s %s %s %s" % (fixed[19], fixed[20], fixed[21], fixed[22], fixed[23], fixed[24], fixed[25], fixed[26])
  print "* Data Payload Size: 0x%s%s" % (fixed[27], fixed[28])
  print "*---------------------------------------------------------------------------------------"

def splithex(data):
  data = binascii.hexlify(data)
  n = 2
  fixed = [data[i:i+n] for i in range(0, len(data), n)]

  return ' '.join(fixed)

con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = (hostname, 5123)
con.setblocking(1)
#con.settimeout(5.0) # If there is no data/activity, this will time out the connection
con.connect(server)
print "[*] Connected..."

# Redo this later
reply = con.recv(256)
req_num = get_req(reply)

if verbose:
  print "[*] REC #1"
  print "FILE REQ# %s" % req_num
  packet_data(reply)

time.sleep(2)

counter = 2
seq_num = 0
req_num = 0
cmd = 0
incoming = 0

# Standard initialization/negotiation ping-pong here. Followed by read operations.
# Yep, a while loop is terrible here, to be fixed later.
while True:
  reply = con.recv(256)

  if verbose:
    print "[*] REC #%s" % counter
    packet_data(reply)
  time.sleep(1)
  incoming = get_incoming_data(reply)

  seq_num = incoming[0]
  req_num = incoming[1][0]
  cmd = incoming[1][4:]

  if verbose:
    print "[***] SEQ: %s" % seq_num
    print "[***] REQ: %s" % req_num

  # SCSI -- 25h READ CAPACITY (10)
  if cmd == ['01', '25']:
#                                                                       This is a very important packet, it tells the system the size of the disk
#									e.g.: kernel: sd 548:0:0:0: [sdb] 2880 512-byte logical blocks: (1.47 MB/1.40 MiB)
    send_packet = build_packet("00", "2500", seq_num, "08000000"+req_num+"00000001250000000000000000000000000000000800000000000b3f00000200")
    con.send(send_packet)
  elif cmd == ['01', '28']:
    print "Start reading blocks..."
    if verbose: print incoming[1]
    break
  else:
    send_packet = build_packet("00", "1d00", seq_num, "00000000"+''.join(incoming[2]))
    con.send(send_packet)
  counter += 1

file = open('fdboot.img', 'rb')
zero_pos = file.tell()
file.seek(0, os.SEEK_END)
file_size = file.tell()
file.seek(zero_pos, os.SEEK_SET)

if verbose: print "[***] FILE REQ#: %s" % req_num

# Set up some stuff here
con.settimeout(5.0) # We want to time out if we don't get a reply... at least for the first packet
data_sent = 0 # Counter of how much data we've sent
read_size = 4096 # Temporary, will be modified as needed below

print "[*] Ready, mount the image..."

while True:
  try:
    reply = con.recv(256)
    incoming = get_incoming_data(reply)

    if verbose:
      print "[***] READ REC'D:"
      packet_data(reply)

    seq_num = incoming[0]
    req_num = incoming[1][0]
    cmd = incoming[1][4:7]

    if verbose:
      print "[***] IUSB PKT SEQ#: %s" % seq_num
      print "[***] DATA PKT REQ#: %s" % req_num
      print "[***] SCSI  COMMAND: %s" % cmd   

  except KeyboardInterrupt:
    print "Exiting..."
    con.close()
    sys.exit(0)
  except:
    pass # Got nothing to recieve, continue.
  
  # This is to pass our first wait, need to fix this. Once negotiation goes to file transfer, we have one lapse of recieve
  con.settimeout(None)

  # * ----------------------- *
  # Note to self: SCSI is Big-Endian
  # 1 Block = 512 bytes
  # * ----------------------- *

  # SCSI -- 28h  READ(10)
  if cmd == ['01', '28']:
    file.seek(0, os.SEEK_SET) # Since we'll be jumping back and forth in the file, ZERO it before and after read operations
    data_packet_command = get_full_incoming_data_packet(reply)
    if verbose: scsi_packet_data(''.join(data_packet_command))
   
    # How many logical blocks to transfer * 512. E.g: 1x512 = 512. 8x512 = 4096
    blocks_to_read = int(str(''.join(data_packet_command[16:18])), 16)
    scsi_read_cmd_size = ['28', '00', '00', '00', '00', '00', '00', '00', blocks_to_read, '00']

    wtf_cmd = incoming[2][10:14] # ex: 10 00 00 08, 00 00 00 20, 00 00 00 01, 13 00 00 01, 14 00 00 01

    data_packet_size = data_packet_command[:2] #'02' #data_packet_command[26]

    data_packet_size_send = str('1d' + ''.join(data_packet_size[1])) # Fix this so its not hardcoded

    if verbose:
      print blocks_to_read
      print "WTF: %s" % wtf_cmd
      print data_packet_command
      print data_packet_size
      print data_packet_size_send 

    binary_read_loc = ''.join(data_packet_command[13:15])
    seek_loc = int(binary_read_loc,16) * 512
    file.seek(int(binary_read_loc,16)*512, os.SEEK_SET) # 5th and 6th byte of data_packet_command
    read_size=blocks_to_read * 512

    piece = file.read(read_size)
    loc = file.tell() # In case we need to know where we are in the file

    if verbose:
      print "Location to READ: %s" % int(binary_read_loc, 16)
      print binary_read_loc
      print "# of Blocks to READ: %s" % blocks_to_read
      print "Calculated Read Size: %s\nCalculated Read Location: %s" % (read_size, seek_loc)
      print "* Sending Chunk of Size: %s bytes or %s (Actually sending: %s) " % (len(piece), hex(len(piece))[2:], str(get_size(str(hex(len(piece))[2:]))))

    send_packet = build_data_packet(seq_num, "FAKE", data_packet_size_send, data_packet_command[1], incoming[1], wtf_cmd, data_packet_size, binascii.hexlify(piece))
    length = con.send(send_packet)
    data_sent = data_sent + length

    if verbose:
      print "Total Data Sent (This Session): %s" % data_sent
      print "Data Piece: %s" % len(piece)

    file.seek(0, os.SEEK_SET)
    continue

  # SCSI -- 1E	PREVENT ALLOW MEDIUM REMOVAL
  if cmd == ['01', '1e']:
    send_packet = build_packet("00", "1d00", seq_num, "00000000"+''.join(incoming[2]))
    con.send(send_packet)
    if verbose: print "Ready for next operation..."
    continue

  # SCSI -- 00h	TEST UNIT READY
  if cmd == ['01', '00']:
    send_packet = build_packet("00", "1d00", seq_num, "00000000"+''.join(incoming[2]))
    con.send(send_packet)
    if verbose: print "Test for readiness..."
    continue

  # SCSI -- 25h  READ CAPACITY(10)
  if cmd == ['01', '25']:
    lba_count = "00000b3f" # Last LBA starting from 0 (0xb3f == 2879)
    bs = "00000200" # Block size in Bytes (0x200 == 512)
    send_packet = build_packet("00", "2500", seq_num, "08000000"+req_num+"000000012500000000000000000000000000000008000000"+lba_count+bs)
    con.send(send_packet)
    if verbose: print "Read media capacity..."
    continue

  # SCSI -- 5Ah	MODE SENSE(10)
  # http://www.seagate.com/staticfiles/support/disc/manuals/scsi/100293068a.pdf
  # http://www-01.ibm.com/support/knowledgecenter/STCMML8/com.ibm.storage.ts3500.doc/sref_3584_mcmsn10.html
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

  # SCSI -- 2Ah WRITE(10)
  # This fixes the "timeout" issue after mounting image, we just ignore the write basically.
  if cmd == ['02', '2a']:
    if verbose: print "Write attempted... "
    send_packet = build_packet("00", "1d00", seq_num, "00000000"+req_num+"000000022a00000000130000010000000000000000000000")
    con.send(send_packet)
    continue

  if cmd == ['00', 'f1']:
    print "Transfer Complete... doing Keep-Alive..."

    # This appears to just be a ping/ping
    send_packet = binascii.unhexlify("4955534220202020000000ff1d00000000000080000000000000000000000000000000000000000000f100000000000000000000000105200000000000")
    if verbose: packet_data(send_packet)
    con.send(send_packet)
    continue
  else:
    # Ignore everything else here, with commands like 2Ah we get multiple packets of data with no headers, so don't choke on that.
    if verbose: packet_data(reply)
    pass

con.close()
file.close()
print "We should never really get here."
time.sleep(30)

sys.exit(0)
