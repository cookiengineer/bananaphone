# Cross-platform EDL mode usage guide for Qualcomm-based KaiOS devices

Here is the basic guide of how to use EDL mode of Qualcomm-based devices (we're interested in the ones running KaiOS and having the most basic bootloaders) without any proprietary dependency like QFIL. The `edl.py` utility used in this guide was originally created by B. Kerler and its snapshot (working for our MSM8905 devices) can be fetched from this repository.

## Prerequisites

- Python 3.7 64-Bit
- android-platform-tools (ADB, Fastboot)
- EDL firehose loader binaries for your devices (some of the known KaiOS device loaders can be found [here](http://edl.bananahackers.net/))

### Installation details

- Install the dependencies: `sudo -H pip3 install pyusb pyserial capstone keystone-engine`

Additionally, if you're running Linux and having issues with device access:

- Append `blacklist qcserial` to `/etc/modprobe.d/blacklist.conf`
- Copy 51-edl.rules to `/etc/udev/rules.d`
- Copy 50-android.rules to `/etc/udev/rules.d`


## Operation

All further examples are provided for CAT B35.

### Checking whether the firehose works

For this purpose, just use `edl.py` with a single `-loader` parameter:

```
python3 edl.py -loader generic_CAT_B35.mbn
```

You should see something like this:

```
Using loader generic_CAT_B35.mbn ...
Waiting for the device
Device detected :)
Mode detected: Sahara

------------------------
HWID:              0x000940e100000000 (MSM_ID:0x000940e1,OEM_ID:0x0000,MODEL_ID:0x0000)
PK_HASH:           0xcc3153a80293939b90d02d3bf8b23e0292e452fef662c74998421adad42a380f
Serial:            0x16b9acb5
SBL Version:       0x00000000

Successfully uploaded programmer :)
TargetName=MSM8909
MemoryName=eMMC
Version=1
Unknown/Missing command, a command is required.
```

If you don't see the "Successfully uploaded programmer" message, that means the loader binary doesn't work as expected (wrong signature, wrong format etc) and you need a different one.

Note that you should supply the loader in any further command, but it may also work without it if the loader has already been sent and accepted successfully.

### Getting partition layout

First, using the `edl.py`, get the partition table layout with `-printgpt` option:

```
python3 edl.py -loader generic_CAT_B35.mbn -printgpt
```

You should get something like this:

```
GPT Table:
-------------
modem:               Offset 0x0000000004000000, Length 0x0000000004000000, Flags 0x00000010, UUID 57ffe7f2-aa66-6de8-4925-6e456356ed0f, Type EFI_BASIC_DATA
sbl1:                Offset 0x0000000008000000, Length 0x0000000000080000, Flags 0x00000000, UUID f4d0d804-0d40-b192-52e1-037b21fc5d34, Type 0xdea0ba2c
sbl1bak:             Offset 0x0000000008080000, Length 0x0000000000080000, Flags 0x00000000, UUID fa17d830-faac-f42e-1ca6-e5f3909ed83d, Type 0xdea0ba2c
aboot:               Offset 0x0000000008100000, Length 0x0000000000100000, Flags 0x00000000, UUID 72348d8d-8980-e1e0-2147-cd4bfb15cc76, Type 0x400ffdcd
abootbak:            Offset 0x0000000008200000, Length 0x0000000000100000, Flags 0x00000000, UUID 15ae6f30-62fe-535d-26e8-7b45ec3f2f61, Type 0x400ffdcd
rpm:                 Offset 0x0000000008300000, Length 0x0000000000080000, Flags 0x00000000, UUID 621608ec-4c27-408b-88f6-f7112f08bff2, Type 0x98df793
rpmbak:              Offset 0x0000000008380000, Length 0x0000000000080000, Flags 0x00000000, UUID 7d8b0a0a-a13c-aaac-0c2f-af22770dd414, Type 0x98df793
tz:                  Offset 0x0000000008400000, Length 0x00000000000c0000, Flags 0x00000000, UUID 006b839f-92b4-e8ea-eed6-4e322c99fa16, Type 0xa053aa7f
tzbak:               Offset 0x00000000084c0000, Length 0x00000000000c0000, Flags 0x00000000, UUID 11a435f8-89be-672c-6045-df71b4271292, Type 0xa053aa7f
pad:                 Offset 0x0000000008580000, Length 0x0000000000100000, Flags 0x00000000, UUID 5225287f-492b-eda3-7027-a441b7ea6379, Type EFI_BASIC_DATA
modemst1:            Offset 0x0000000008680000, Length 0x0000000000180000, Flags 0x00000000, UUID 6d11e78e-bd73-b78b-339d-0f882b09157b, Type 0xebbeadaf
modemst2:            Offset 0x0000000008800000, Length 0x0000000000180000, Flags 0x00000000, UUID 617e5535-6e7c-2a68-90ed-774949fd395e, Type 0xa288b1f
misc:                Offset 0x0000000008980000, Length 0x0000000000100000, Flags 0x00000000, UUID d0b3277d-6bec-27fd-5a02-4c8eff5abc7a, Type 0x82acc91f
fsc:                 Offset 0x0000000008a80000, Length 0x0000000000000400, Flags 0x00000000, UUID 95419db9-c3cc-9d51-7dca-e7fddb0cea10, Type 0x57b90a16
ssd:                 Offset 0x0000000008a80400, Length 0x0000000000002000, Flags 0x00000000, UUID cfa7e216-23da-8e3b-9165-b730314789ca, Type 0x2c86e742
splash:              Offset 0x0000000008a82400, Length 0x0000000000a00000, Flags 0x00000000, UUID f59b020c-7407-578b-d8f4-7608c01dbbe1, Type 0x20117f86
DDR:                 Offset 0x000000000c000000, Length 0x0000000000008000, Flags 0x00000010, UUID bbf8967c-4e6b-aaee-8a1d-d1536fd84c2d, Type 0x20a0c19c
fsg:                 Offset 0x000000000c008000, Length 0x0000000000180000, Flags 0x00000010, UUID 0fe0230c-96c2-7c89-8325-16343e46d20f, Type 0x638ff8e2
sec:                 Offset 0x000000000c188000, Length 0x0000000000004000, Flags 0x00000010, UUID 52a9a7ef-d31f-045a-cb5a-0da0a0ea29b1, Type 0x303e6ac3
boot:                Offset 0x000000000c18c000, Length 0x0000000002000000, Flags 0x00000010, UUID 76b6ddd6-e0fd-b9b9-904b-9755e3004bcd, Type 0x20117f86
system:              Offset 0x000000000e18c000, Length 0x0000000032000000, Flags 0x00000010, UUID 44324c55-8d39-e368-b65d-dac68e38d9fe, Type 0x97d7b011
persist:             Offset 0x000000004018c000, Length 0x0000000002000000, Flags 0x00000010, UUID cb64d7de-70c8-0a8e-a7db-3cdacdf1b69e, Type 0x6c95e238
usbmsc:              Offset 0x0000000044000000, Length 0x000000003e800000, Flags 0x00000000, UUID c2146c4f-d77a-c9a0-5837-f41dcbd5d68a, Type 0x1b81e7e6
cache:               Offset 0x0000000084000000, Length 0x0000000010000000, Flags 0x00000010, UUID 9709b46c-0313-18e5-04ca-65e6a53d6ea2, Type 0x5594c694
recovery:            Offset 0x0000000094000000, Length 0x0000000002000000, Flags 0x00000010, UUID d704a802-32ef-8ffd-4663-0efcea08a944, Type 0x9d72d4e4
devinfo:             Offset 0x0000000096000000, Length 0x0000000000100000, Flags 0x00000010, UUID c8f83c34-31bd-df17-ceb8-75729f2c3e07, Type 0x1b81e7e6
keystore:            Offset 0x0000000098000000, Length 0x0000000000080000, Flags 0x00000000, UUID 99b6c311-2a4c-63fc-66fa-e3a3c2b028d4, Type 0xde7d4029
oem:                 Offset 0x0000000098080000, Length 0x0000000004000000, Flags 0x00000000, UUID a1f340a8-8e47-272a-d5d9-9da01a615bfb, Type 0x7db6ac55
config:              Offset 0x000000009c080000, Length 0x0000000000080000, Flags 0x00000000, UUID 668ac29d-5cb3-22d8-81d7-1c0f69ef6c1a, Type 0x91b72d4d
userdata:            Offset 0x000000009c100000, Length 0x000000004fefbe00, Flags 0x00000000, UUID 80d928b2-abc2-3586-5276-c31952ae4cb0, Type 0x1b81e7e6
```

You can also dump the raw partition table into a file with `-gpt [filename]` option, like this:

```
python3 edl.py -loader generic_CAT_B35.mbn -gpt gpt.img
```

Same goes for PBL (`-pbl [filename]`), memory table (`-memtbl [filename]`) and QFPROM contents (`-qfp [filename]`), in case you ever need them:

```
python3 edl.py -loader generic_CAT_B35.mbn -pbl pbl.img
python3 edl.py -loader generic_CAT_B35.mbn -memtbl memtbl.img
python3 edl.py -loader generic_CAT_B35.mbn -qfp qfprom.img
```

### Partition readback

Now, when we have the partition list, we can backup any partition from the device with `-r [partname] [filename]` option. For instance:

```
python3 edl.py -loader generic_CAT_B35.mbn -r recovery recovery.img
```

This will save the recovery partition contents into the `recovery.img` file. The `edl.py` utility also allows raw sector-to-sector readback but you're welcome to see the command help yourself if you need to do this.

### Partition erasing and flashing

Finally, this is the functionality we need most (along with readback, of course).

To erase a partition, supply the `-e [partname]` option:

```
python3 edl.py -loader generic_CAT_B35.mbn -e recovery
```

To flash a new partition image, supply the `-w [partname] [filename]` option:

```
python3 edl.py -loader generic_CAT_B35.mbn -w recovery recovery.img
```

This will write the recovery partition contents from the `recovery.img` file. The `edl.py` utility also allows raw sector-to-sector writing but you're welcome to see the command help yourself if you need to do this.

### Device rebooting

After you're done with all necessary operations, it's convenient to reboot the device into a normal mode with `-reset` option:

```
python3 edl.py -loader generic_CAT_B35.mbn -reset
```

## Credits

Original `edl.py` utility and installation instructions: &copy; B.Kerler 2018

Guide with examples: &copy; Luxferre 2019
