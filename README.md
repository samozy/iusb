## IUSB - Virtual Media Protocol
#### Documentation, research, simulation.

**Changelog**:

07/22/15 - Adding initial commit of Wireshark Dissector and a very early, dirty Python script to talk the protocol.

07/30/15 - Updated Python script a bit. Successfully serves the file, and can be queried from OS. Still need to fix some data transfer things but this one actually works for the most part. ToDo: Split up Data packet to extract command/size/data/etc.

07/31/15 - I just realized the encapsulated data in the IUSB packet is SCSI. Derp. Rewriting a lot of things.

08/07/15 - Uploading an actual working "simulator" of IUSB Floppy Image server... it works!

#### Frequently UnAsked Questions

**_What is IUSB?_**
- IUSB (no, not the other iUSB you're thinking of) is a "protocol" used by some board manufacturers like Asus, Dell (non-iDRAC), SuperMicro and Tyan to allow you to mount remote media (Floppy/CD-ROM) via the Baseboard Management Controller (BMC). In turn you are able to boot your server from a remote drive or binary image to do things such as OS installations, Firmware updates, etc. The Virtual Media service listens on TCP ports 5120 and 5123 on the BMC network interface (here's some reading from SM: [http://www.supermicro.com/support/faqs/faq.cfm?faq=9626]). Once a connection on one of these ports is made, there is some magic that happens. Read on.

**_Why is this code even here?_**
- Long story short, I needed to mount a bootable DOS floppy image (.img) on a server in a DC. The first problem was it was remote, the 2nd problem was... the floppy drive does not exist. After a bit of research I realized remote Virtual Media was available. The only problem is... it requires *JAVA* (gasp). I did what I had to (in a VM, luckily) and used the JAVA client to do my business. I felt gross after. In case I had to do this again, I looked around for a better alternative (native software for *nix/Win?). After many, many, MANY long weeks of searching for software, protocol explanations (I thought I can always write a tool) I came up completely empty. This is how this came to be.

**_No, really, why? And how?_**
- The story is long, but the summary is... I tried brute forcing it (yep, just dump the binary disk via nc!), trickery, and magic spells. I ended up repeating the process of using JAVA (ugh) and sniffing packets with Wireshark all along learning about how the protocol works from there. I wrote a Dissector ([https://github.com/samozy/iusb/blob/master/iusb.lua]) in LUA as a plug-in to try to help me make sense of what I was seeing. I obviously guessed on a lot of things as I don't have the original source to this whole system or any kind of specs. After a few weeks of trying to dissassemble the packets to learn what they did, I began seeing patterns and started a Python script to simply parrot-back the operations as I was seeing them in the PCAP. This worked for the most part, but I had to dig deeper to actually having a functional mounted disk. I might do a write-up, but it took a long time and a lot of guessing.

**_Who cares?_**
- I do. I learned a lot about a seemingly undocumented (AFAICT, many google searches later) protocol and was able to create a working tool to successfully imitate a terrible JAVA app. It was a fun challenge.

**_Does it work?_**
- Sure does! As of this point, and as you can see in the changelog, it only emulates interaction with a Floppy image. It works reliably enough to the point that the OS can query the drive, mount it, read/seek contents and as of recent is stable enough to be called "working" (the last step was fixing random disconnects).

**_What exactly is IUSB from your experience?_**
- When all the right buttons are pushed, it is a a wrapper for SCSI. That's it. There are some non-SCSI interaction packets but those are boring. The Python code you can see in this repo basically fosters interaction of reading the binary image, communication on the SCSI layer, the "drive" connected via virtual USB and the local OS. The OS interacts with the drive as if it were a local SCSI device connected via the USB bus (yeah...). The BMC provides the magic to make the system think a new USB device was attached, the device appears to be an emulated SCSI device to the OS and the rest is history. I basically wrote a wrapper to speak SCSI, I guess :/

**_What does it look like?_**
- Just for kicks, this is what you get when you connect to the Virtual Media port:
```
[mozy@iron ~]$ telnet waffle 5123
Trying 192.168.0.33...
Connected to 192.168.0.33.
Escape character is '^]'.
IUSB    7�^]quit

...

If you capture the output via netcat, the binary "response" looks like this:

[mozy@iron ~]$ xxd IUSB_response.bin
0000000: 4955 5342 2020 2020 0000 0000 3700 0000  IUSB    ....7...
0000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0000020: 0000 0000 0000 0000 00f1 0000 0000 0000  ................
0000030: 0000 0000 0000 0000 0000 0000 0000 0100  ................
0000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0000050: 0000 0000 0000 0049 5553 4220 2020 2001  .......IUSB    .
0000060: 0020 8b1d 0000 0000 8001 0002 0000 0001  . ..............
0000070: 0000 0000 0000 0000 0000 0002 0000 0001  ................
0000080: 0000 0000 0000 0000 0000 0000 0000 0000  ................
0000090: 0000 0000  
```
- Here is what the OS sees when the "device is connected" (when you open a connection to TCP port 5123):
```
Jul 21 00:06:54 waffle kernel: usb 1-5.2: new high speed USB device using ehci_hcd and address 26
Jul 21 00:06:54 waffle kernel: usb 1-5.2: device descriptor read/64, error -71
Jul 21 00:06:54 waffle kernel: usb 1-5.2: New USB device found, idVendor=046b, idProduct=ff40
Jul 21 00:06:54 waffle kernel: usb 1-5.2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
Jul 21 00:06:54 waffle kernel: usb 1-5.2: Product: Virtual Floppy Device
Jul 21 00:06:54 waffle kernel: usb 1-5.2: Manufacturer: American Megatrends Inc.
Jul 21 00:06:54 waffle kernel: usb 1-5.2: SerialNumber: serial
Jul 21 00:06:54 waffle kernel: usb 1-5.2: configuration #1 chosen from 1 choice
Jul 21 00:06:54 waffle kernel: scsi28 : SCSI emulation for USB Mass Storage devices
```
- Here is what we see when we successfully mount the image (this took a WHILE to get working):
```
Jul 21 00:06:54 waffle kernel: scsi28 : SCSI emulation for USB Mass Storage devices
Jul 21 00:06:55 waffle kernel: scsi 28:0:0:0: Direct-Access     AMI      Virtual Floppy   1.00 PQ: 0 ANSI: 0 CCS
Jul 21 00:06:55 waffle kernel: sd 28:0:0:0: Attached scsi generic sg3 type 0
Jul 21 00:06:55 waffle kernel: sd 28:0:0:0: [sdc] 2880 512-byte logical blocks: (1.47 MB/1.40 MiB)
Jul 21 00:06:55 waffle kernel: sd 28:0:0:0: [sdc] Assuming Write Enabled
Jul 21 00:06:55 waffle kernel: sd 28:0:0:0: [sdc] Assuming drive cache: write through
Jul 21 00:06:55 waffle kernel: sd 28:0:0:0: [sdc] Assuming Write Enabled
Jul 21 00:06:55 waffle kernel: sd 28:0:0:0: [sdc] Assuming drive cache: write through
Jul 21 00:06:55 waffle kernel: sdc:
Jul 21 00:06:55 waffle kernel: sd 28:0:0:0: [sdc] Assuming Write Enabled
Jul 21 00:06:55 waffle kernel: sd 28:0:0:0: [sdc] Assuming drive cache: write through
Jul 21 00:06:55 waffle kernel: sd 28:0:0:0: [sdc] Attached SCSI removable disk
```
- When we finally mount the "disk" we can query it:
```
-bash-4.1# smartctl -ax /dev/sdc -d scsi
smartctl 5.43 2012-06-30 r3573 [x86_64-linux-2.6.32-220.23.1.el6.x86_64] (local build)
Copyright (C) 2002-12 by Bruce Allen, http://smartmontools.sourceforge.net

Vendor:               AMI
Product:              Virtual Floppy
Revision:             1.00
User Capacity:        1,474,560 bytes [1.47 MB]
Logical block size:   512 bytes
Serial number:
Device type:          disk
Local Time is:        Tue Jul 21 00:07:40 2015 UTC
Device does not support SMART

Error Counter logging not supported
Device does not support Self Test logging
Device does not support Background scan results logging
scsiPrintSasPhy Log Sense Failed [unsupported scsi opcode]
-bash-4.1#
```
- Now let's mount a basic FreeDOS image:
```
-bash-4.1# mount /dev/sdc /mnt
-bash-4.1# cd /mnt
-bash-4.1# ls
command.com  driver  fdconfig.sys  freedos  kernel.sys
```
- Looks great! Now let's check the partition table....
```
Insert terrible output later, no clue what it means.
```
- So does your code REALLY work? Prove it!
```
-bash-4.1# mount -t vfat /dev/sdb /mnt
-bash-4.1# cd /mnt
-bash-4.1# ls
command.com  driver  fdconfig.sys  freedos  kernel.sys
-bash-4.1# cat fdconfig.sys
; FreeDOS 1.0 Final distro  by Blair Campbell [Blairdude@gmail.com],
; last update 2005-08-02 by Blair Campbell [Blairdude@gmail.com]
; config.sys loads system drivers. Please edit to suit your needs.
;!SWITCHES=/E
!SWITCHES=/N
menucolor=7,0
MENU     �������������������������������������������������������������������ͻ
MENU     �       FreeDOS 1.0 Final (2006-July-30) INSTALLATION/LIVE CD       �
MENU     �������������������������������������������������������������������͹
MENU     �   1. Install to harddisk using FreeDOS SETUP (default)            �
MENU     �                                                                   �
MENU     �   2. FreeDOS Safe Mode  (don't load any drivers)                  �
MENU     �                                                                   �
MENU     �   3. FreeDOS Live CD with HIMEM + EMM386                          �
MENU     �                                                                   �
MENU     �   4. FreeDOS Live CD with HIMEM only                              �
MENU     �                                                                   �
MENU     �   5. FreeDOS Live CD only                                         �
MENU     �                                                                   �
MENU     �      FreeDOS is a trademark of Jim Hall 1994-2006                 �
MENU     �������������������������������������������������������������������ͼ
MENUDEFAULT=1,120

134?!DEVICE=A:\DRIVER\HIMEM.EXE
3?!DEVICE=A:\DRIVER\EMM386.EXE X=TEST
12345?!SHELL=A:\COMMAND.COM A:\ /E:2048 /F /MSG /P=A:\FREEDOS\FDAUTO.BAT
34?!DEVICEHIGH=A:\DRIVER\XDMA.SYS
345?!DEVICEHIGH=A:\DRIVER\XCDROM.SYS /D:FDCD0000
!DOSDATA=UMB
!DOS=HIGH,UMB
!FILES=20
!BUFFERS=20
!LASTDRIVE=Z
-bash-4.1#
```
- Looks good to me!

**_About your code..._**
- Why does it look so terrible? Why don't you use OOP? Why whatever? Shut up, that's why. This was more of a challenge than a necessity. It works. I'm done.
