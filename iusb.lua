-- Instructions: place me in "$HOME/.wireshark/plugins" and either sniff traffic or open a PCAP.

-- Right now this is hard-coded for TCP port 5123 which is used for Floppy images.
--   I might include CD-ROM filters in this later on as the packet structures are identical.

-- Credit for sample code used here goes to "securez" from http://blog.roisu.org/english-create-a-wireshark-dissector-with-lua/

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
local f_data = ProtoField.bytes("iusb.data", "Packet Data", base.HEX)

protocol_iusb.fields = {f_sig, f_major, f_minor, f_pkt_hdr, f_hdr_cksum, f_data_pkt_len, f_direction, f_dev_num, f_iface_num, f_client_data, f_seq_num, f_res, f_data}

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

end

-- Initialization routine
function protocol_iusb.init()
    local tcp_dissector_table = DissectorTable.get("tcp.port")

    tcp_dissector_table:add(protocol_iusb.prefs["tcp_port"], protocol_iusb)
end
