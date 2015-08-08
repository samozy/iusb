----------------------------------------
--
-- Script-Name: iusb_dissector.lua
--
-- Author: Stan Ayzenberg
-- Copyright (c) 2015, Stan Ayzenberg
--
-- Version: 1.1 (08/05/15)


-- Instructions:
--   Place me in "$HOME/.wireshark/plugins" and either sniff traffic or open a PCAP.

-- Notes:
--   Right now this is hard-coded for TCP port 5123 which is used for Floppy images.
--   I might include CD-ROM filters in this later on as the packet structures are identical.
--   Should work for the most part... might fix some bugs later.

--   Credit for sample code used here goes to "securez" from http://blog.roisu.org/english-create-a-wireshark-dissector-with-lua/

-- create iusb protocol and its fields
protocol_iusb = Proto ("iusb","IUSB")
 
local f_sig = ProtoField.string("iusb.sig", "Protocol Signature", FT_STRING)
local f_major = ProtoField.uint32("iusb.major", "Major")
local f_minor = ProtoField.uint32("iusb.minor", "Minor")
local f_pkt_hdr = ProtoField.uint32("iusb.pkt_hdr", "Packet Header Len")
local f_hdr_cksum = ProtoField.uint32("iusb.hdr_cksum", "Header Checksum", base.HEX)
local f_data_pkt_len = ProtoField.uint32("iusb.data_pkt_len", "Data Packet Length")
local f_direction = ProtoField.bytes("iusb.direction", "Data Direction", base.HEX)
local f_dev_num = ProtoField.bytes("iusb.dev_num", "Device Number")
local f_iface_num = ProtoField.uint32("iusb.iface_num", "Interface Number")
local f_client_data = ProtoField.uint32("iusb.client_data", "Client Data (Command/Response?)", base.HEX)
local f_seq_num = ProtoField.uint32("iusb.seq_num", "Sequence Number Echo", base.HEX)
local f_res = ProtoField.uint32("iusb.res", "Reserved Space", base.HEX)
local f_data = ProtoField.bytes("iusb.data", "Raw Packet Data", base.HEX)

-- Lets try to describ our data packet
-- It just encapsulates SCSI...
local pkt_req_size = ProtoField.uint32("iusb.pkt_req_size", "Request Size", base.HEX)
local pkt_filler0 = ProtoField.uint32("iusb.pkt_filler0", "Filler #0", base.HEX)
local pkt_seq = ProtoField.uint32("iusb.pkt_seq", "Packet Sequence #", base.HEX)
local pkt_filler1 = ProtoField.uint32("iusb.pkt_filler1", "Filler #1", base.HEX)
local pkt_cmd = ProtoField.uint32("iusb.pkt_cmd", "Packet Command", base.HEX)
local pkt_filler2 = ProtoField.uint32("iusb.pkt_filler2", "Filler #2", base.HEX)
local pkt_read_loc = ProtoField.uint32("iusb.pkt_read_loc", "Image Read offset (x2?)", base.HEX)
local pkt_unknwn = ProtoField.bytes("iusb.pkt_unknwn", "Unknown", base.HEX)
local pkt_rec_size = ProtoField.uint32("iusb.pkt_rec_size", "Packet Buffer Recieve Data Size", base.HEX)
local pkt_filler3 = ProtoField.uint32("iusb.pkt_filler3", "Filler #3", base.HEX)
local pkt_payload = ProtoField.bytes("iusb.pkt_payload", "Data Payload", base.HEX)

protocol_iusb.fields = {f_sig, f_major, f_minor, f_pkt_hdr, f_hdr_cksum, f_data_pkt_len, f_direction, f_dev_num, f_iface_num, f_client_data, f_seq_num, f_res, f_data, pkt_req_size, pkt_filler0, pkt_seq, pkt_filler1, pkt_cmd, pkt_filler2, pkt_read_loc, pkt_unknwn, pkt_rec_size, pkt_filler3, pkt_payload}
 
-- Set the preferences to listen on TCP 5123
protocol_iusb.prefs["tcp_port"] = Pref.uint("TCP Port", 5123, "TCP Port for IUSB (Floppy)")

-- iusb dissector function
function protocol_iusb.dissector (buf, pinfo, root)
  
  pinfo.cols.protocol = protocol_iusb.name
 
  -- create subtree for iusb
  subtree = root:add(protocol_iusb, buf(), "IUSB Protocol / Virtual Media (Floppy/CD-ROM)")
  -- add protocol fields to subtree
  subtree:add(f_sig, buf(0,8))
  subtree:add(f_major, buf(8,1))
  subtree:add(f_minor, buf(9,1))
  subtree:add(f_pkt_hdr, buf(10,1))
  subtree:add(f_hdr_cksum, buf(11,1))
  
  -- The Data Packet Length is a 2-byte little-endian value
  subtree:add_le(f_data_pkt_len, buf(12,2)):append_text(" Bytes") --buf(12,1))
  
  subtree:add(f_dev_num, buf(17, 1))
  subtree:add(f_iface_num, buf(18, 1))

  -- Check direction of data flow, this can probably be cleaner.
  local flags = buf(19,1):uint()
  local flags_s = {}
  if bit.band(flags, 0x80) > 0 then table.insert(flags_s, "TX") else table.insert(flags_s, "RX") end
  subtree:add(f_direction, buf(19,1)):append_text(" (" .. table.concat(flags_s, ", ") .. ")")

  subtree:add(f_client_data, buf(20, 4))
  subtree:add(f_seq_num, buf(24, 1))
  subtree:add(f_res, buf(25, 4))
  
  -- Actual data packet is past 32-byte header and length is determined from f_data_pkt_len
  subtree:add(f_data, buf(32, buf(12,2):le_int()))

  -- Add a tree for our Data Packet (SCSI). Need to figure out how to add a nested tree, later.
  datatree = root:add(protocol_iusb, buf(32, buf(12,2):le_int()), "Junk in the Data Packet Trunk")

  datatree:add_le(pkt_req_size, buf(32,2))
  datatree:add(pkt_filler0, buf(34,2))
  datatree:add(pkt_seq, buf(36,1))
  datatree:add(pkt_filler1, buf(37,3))
  datatree:add(pkt_cmd, buf(40,2))
  datatree:add(pkt_filler2, buf(42,3))
  datatree:add(pkt_read_loc, buf(45,2))
  datatree:add(pkt_unknwn, buf(47,10)) -- Sometimes its 01 sometimes 08
  datatree:add_le(pkt_rec_size, buf(57,2))
  datatree:add(pkt_filler3, buf(59,2))
  datatree:add(pkt_payload, buf(61, 1)) -- ### FIX THIS

end
 
-- Initialization routine
function protocol_iusb.init()
    local tcp_dissector_table = DissectorTable.get("tcp.port")
 
    tcp_dissector_table:add(protocol_iusb.prefs["tcp_port"], protocol_iusb)
end
