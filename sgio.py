import ctypes
import fcntl
import string

SPC_SK_ILLEGAL_REQUEST = 0x5

SG_DXFER_NONE = -1          # SCSI Test Unit Ready command
SG_DXFER_TO_DEV = -2        # SCSI WRITE command
SG_DXFER_FROM_DEV = -3      # SCSI READ command

ASCII_S = 83
SG_IO = 0x2285              # <scsi/sg.h>


debug = 0
ata_status = 0
ata_error = 0

smartStrings = {
    1: "Raw_Read_Error_Rate ",
    2: "Throughput_Performance ",
    3: "Spin_Up_Time ",
    4: "Start_Stop_Count ",
    5: "Reallocated_Sector_Ct ",
    6: "Read_Channel_Margin ",
    7: "Seek_Error_Rate ",
    8: "Seek_Time_Performance ",
    9: "Power_On_Hours ",
    10: "Spin_Retry_Count ",
    11: "Calibration_Retry_Count ",
    12: "Power_Cycle_Count ",
    13: "Read_Soft_Error_Rate ",
    175: "Program_Fail_Count_Chip ",
    176: "Erase_Fail_Count_Chip ",
    177: "Wear_Leveling_Count ",
    178: "Used_Rsvd_Blk_Cnt_Chip ",
    179: "Used_Rsvd_Blk_Cnt_Tot ",
    180: "Unused_Rsvd_Blk_Cnt_Tot ",
    181: "Program_Fail_Cnt_Total ",
    182: "Erase_Fail_Count_Total ",
    183: "Runtime_Bad_Block ",
    184: "End-to-End_Error ",
    187: "Reported_Uncorrect ",
    188: "Command_Timeout ",
    189: "High_Fly_Writes ",
    190: "Airflow_Temperature_Cel ",
    191: "G-Sense_Error_Rate ",
    192: "Power-Off_Retract_Count ",
    193: "Load_Cycle_Count ",
    194: "Temperature_Celsius ",
    195: "Hardware_ECC_Recovered ",
    196: "Reallocated_Event_Count ",
    197: "Current_Pending_Sector ",
    198: "Offline_Uncorrectable ",
    199: "UDMA_CRC_Error_Count ",
    200: "Multi_Zone_Error_Rate ",
    201: "Soft_Read_Error_Rate ",
    202: "Data_Address_Mark_Errs ",
    203: "Run_Out_Cancel ",
    204: "Soft_ECC_Correction ",
    205: "Thermal_Asperity_Rate ",
    206: "Flying_Height ",
    207: "Spin_High_Current ",
    208: "Spin_Buzz ",
    209: "Offline_Seek_Performnce ",
    220: "Disk_Shift ",
    221: "G-Sense_Error_Rate ",
    222: "Loaded_Hours ",
    223: "Load_Retry_Count ",
    224: "Load_Friction ",
    225: "Load_Cycle_Count ",
    226: "Load-in_Time ",
    227: "Torq-amp_Count ",
    228: "Power-off_Retract_Count ",
    230: "Head_Amplitude ",
    231: "Temperature_Celsius ",
    232: "Available_Reservd_Space ",
    233: "Media_Wearout_Indicator ",
    240: "Head_Flying_Hours ",
    241: "Total_LBAs_Written ",
    242: "Total_LBAs_Read ",
    250: "Read_Error_Retry_Rate ",
    254: "Free_Fall_Sensor "
}


class ataCmd(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('opcode', ctypes.c_ubyte),
        ('protocol', ctypes.c_ubyte),
        ('flags', ctypes.c_ubyte),
        ('features', ctypes.c_ushort),
        ('sector_count', ctypes.c_ushort),
        ('lba_h_low', ctypes.c_ubyte),
        ('lba_low', ctypes.c_ubyte),
        ('lba_h_mid', ctypes.c_ubyte),
        ('lba_mid', ctypes.c_ubyte),
        ('lba_h_high', ctypes.c_ubyte),
        ('lba_high', ctypes.c_ubyte),
        ('device', ctypes.c_ubyte),
        ('command', ctypes.c_ubyte),
        ('control', ctypes.c_ubyte)]


class sgioHdr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ('interface_id', ctypes.c_int),      # [i] 'S' for SCSI generic (required)
        ('dxfer_direction', ctypes.c_int),   # [i] data transfer direction
        ('cmd_len', ctypes.c_ubyte),         # [i] SCSI command length ( <= 16 bytes)
        ('mx_sb_len', ctypes.c_ubyte),       # [i] max length to write to sbp
        ('iovec_count', ctypes.c_ushort),    # [i] 0 implies no scatter gather
        ('dxfer_len', ctypes.c_uint),        # [i] byte count of data transfer
        ('dxferp', ctypes.c_void_p),         # [i], [*io] points to data transfer memory
        ('cmdp', ctypes.c_void_p),           # [i], [*i] points to command to perform
        ('sbp', ctypes.c_void_p),            # [i], [*o] points to sense_buffer memory
        ('timeout', ctypes.c_uint),          # [i] MAX_UINT->no timeout (unit: millisec)
        ('flags', ctypes.c_uint),            # [i] 0 -> default, see SG_FLAG...
        ('pack_id', ctypes.c_int),           # [i->o] unused internally (normally)
        ('usr_ptr', ctypes.c_void_p),        # [i->o] unused internally
        ('status', ctypes.c_ubyte),          # [o] scsi status
        ('masked_status', ctypes.c_ubyte),   # [o] shifted, masked scsi status
        ('msg_status', ctypes.c_ubyte),      # [o] messaging level data (optional)
        ('sb_len_wr', ctypes.c_ubyte),       # [o] byte count actually written to sbp
        ('host_status', ctypes.c_ushort),    # [o] errors from host adapter
        ('driver_status', ctypes.c_ushort),  # [o] errors from software driver
        ('resid', ctypes.c_int),             # [o] dxfer_len - actual_transferred
        ('duration', ctypes.c_uint),         # [o] time taken by cmd (unit: millisec)
        ('info', ctypes.c_uint)]             # [o] auxiliary information


def swap16(x):
    return ((x << 8) & 0xFF00) | ((x >> 8) & 0x00FF)


def swapString(strg):
    s = []
    for x in range(0, len(strg) - 1, 2):
        s.append(chr(strg[x + 1]))
        s.append(chr(strg[x]))
    return ''.join(s).strip()


def prepareSgio(cmd, feature, count, lba, direction, sense, buf):
    if direction == SG_DXFER_FROM_DEV:
        buf_len = ctypes.sizeof(buf)
        buf_p = ctypes.cast(buf, ctypes.c_void_p)
        prot = 4 << 1  # PIO Data-In
    elif direction == SG_DXFER_TO_DEV:
        buf_len = ctypes.sizeof(buf)
        buf_p = ctypes.cast(buf, ctypes.c_void_p)
        prot = 5 << 1  # PIO Data-Out
    else:
        buf_len = 0
        buf_p = None
        prot = 3 << 1  # Non-data

    if cmd != 0xb0:  # not SMART COMMAND
        prot = prot | 1  # + EXTEND
    sector_lba = lba.to_bytes(6, byteorder='little')

    ata_cmd = ataCmd(opcode=0x85,  # ATA PASS-THROUGH (16)
                     protocol=prot,
                     # flags field
                     # OFF_LINE = 0 (0 seconds offline)
                     # CK_COND = 1 (copy sense data in response)
                     # T_DIR = 1 (transfer from the ATA device)
                     # BYT_BLOK = 1 (length is in blocks, not bytes)
                     # T_LENGTH = 2 (transfer length in the SECTOR_COUNT
                     # field)
                     flags=0x2e,
                     features=swap16(feature),
                     sector_count=swap16(count),
                     lba_h_low=sector_lba[3], lba_low=sector_lba[0],
                     lba_h_mid=sector_lba[4], lba_mid=sector_lba[1],
                     lba_h_high=sector_lba[5], lba_high=sector_lba[2],
                     device=0,
                     command=cmd,
                     control=0)

    sgio = sgioHdr(interface_id=ASCII_S, dxfer_direction=direction,
                   cmd_len=ctypes.sizeof(ata_cmd),
                   mx_sb_len=ctypes.sizeof(sense), iovec_count=0,
                   dxfer_len=buf_len,
                   dxferp=buf_p,
                   cmdp=ctypes.addressof(ata_cmd),
                   sbp=ctypes.cast(sense, ctypes.c_void_p), timeout=1000,
                   flags=0, pack_id=0, usr_ptr=None, status=0, masked_status=0,
                   msg_status=0, sb_len_wr=0, host_status=0, driver_status=0,
                   resid=0, duration=0, info=0)

    return sgio


def printSense(sense):
    print("\nSense:")
    for i in sense:
        strHex = "%0.2X" % int.from_bytes(i, byteorder='little')
        print(strHex, end=" ")
    print()


def printBuf(buf):
    for l in range(0, int(ctypes.sizeof(buf) / 16)):
        intbuf = []
        for i in range(0, 16):
            intbuf.append(chr(int.from_bytes(buf[16 * l + i], byteorder='little')))
        buf2 = [('%02x' % ord(i)) for i in intbuf]
        print('{0}: {1:<39}  {2}'.format(('%07x' % (l * 16)),
                                         ' '.join([''.join(buf2[i:i + 2]) for i in range(0, len(buf2), 2)]),
                                         ''.join([c if c in string.printable[:-5] else '.' for c in intbuf])))


def checkSense(sense, debug):
    global ata_status, ata_error
    response_code = 0x7f & int.from_bytes(sense[0], byteorder='little')
    if response_code >= 0x72:
        sense_key = 0xf & int.from_bytes(sense[1], byteorder='little')
        asc = sense[2]
        ascq = sense[3]
    else:
        if debug:
            print("\nNo sense!")
        return None
    if sense_key == SPC_SK_ILLEGAL_REQUEST:
        if asc == b'\x20' and ascq == b'\x00':
            if debug:
                print("\nATA PASS-THROUGH not supported")
        else:
            if debug:
                print("\nATA PASS-THROUGH bad field in cdb")
                printSense(sense)
    else:
        if sense[8] == b'\x09':
            extend = 1 & int.from_bytes(sense[10], byteorder='little')
            ata_error = int.from_bytes(sense[11], byteorder='little')
            ata_status = int.from_bytes(sense[21], byteorder='little')

            if debug:
                print("\nATA Status Return")
                print("extend={} error={} status={}".format(
                    extend, '0x%02x' % ata_error, '0x%02x' % ata_status))
            return ata_error, ata_status
    return None


def smartGetValues(dev):
    ret = smartReadValues(dev)
    if ret is None:
        return None
    sense, buf = ret
    attributes = {}
    for i in range(30):
        if buf[2 + i * 12] == b'\x00':
            continue
        aid = int.from_bytes(buf[2 + i * 12], byteorder='little')
        pre_fail = int.from_bytes(buf[2 + i * 12 + 1], byteorder='little') & 1
        online = int.from_bytes(buf[2 + i * 12 + 1], byteorder='little') & 2
        current = int.from_bytes(buf[2 + i * 12 + 3], byteorder='little')
        if current == 0 or current == 0xfe or current == 0xff:
            continue
        worst = int.from_bytes(buf[2 + i * 12 + 4], byteorder='little')
        if aid == 3:
            raw = str(int.from_bytes(buf[2 + i * 12 + 5] + buf[2 + i * 12 + 6], byteorder='little')) + \
                " (Average " + str(int.from_bytes(buf[2 + i * 12 + 7] + buf[2 + i * 12 + 8], byteorder='little')) + ")"
        elif aid == 194:
            raw = str(int.from_bytes(buf[2 + i * 12 + 5], byteorder='little')) + " (Min/Max " +\
                str(int.from_bytes(buf[2 + i * 12 + 7], byteorder='little')) + "/" +\
                str(int.from_bytes(buf[2 + i * 12 + 9], byteorder='little')) + ")"
        else:
            raw = str(int.from_bytes(buf[2 + i * 12 + 5] + buf[2 + i * 12 + 6] + buf[2 + i * 12 + 7] +
                                     buf[2 + i * 12 + 8] + buf[2 + i * 12 + 10] + buf[2 + i * 12 + 10], byteorder='little'))
        attributes[aid] = [pre_fail, online, current, worst, raw]
    ret = smartReadThresholds(dev)
    if ret is None:
        return None
    sense, buf = ret
    for i in range(30):
        if buf[2 + i * 12] == b'\x00':
            continue
        aid = int.from_bytes(buf[2 + i * 12], byteorder='little')
        if aid in attributes:
            attributes[aid].append(int.from_bytes(buf[2 + i * 12 + 1], byteorder='little'))
    return attributes


def driveIdentify(dev):
    sense = ctypes.c_buffer(64)
    identify = ctypes.c_buffer(512)
    sgio = prepareSgio(0xec, 0, 0, 0, SG_DXFER_FROM_DEV, sense, identify)  # IDENTIFY
    with open(dev, 'r') as fd:
        if fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio)) != 0:
            return None  # fcntl failed!
    if checkSense(sense, debug) is None:
        return None
    serial = swapString(identify[20:40])
    firmware = swapString(identify[46:53])
    model = swapString(identify[54:93])
    sectors = int.from_bytes(identify[200] + identify[201] + identify[202] + identify[203] +
                             identify[204] + identify[205] + identify[206] + identify[207], byteorder='little')
    return (serial, firmware, model, sectors)


def sectorVerify(dev, start, count):
    sense = ctypes.c_buffer(64)
    sgio = prepareSgio(0x42, 0, count, start, SG_DXFER_NONE, sense, None)  # READ VERIFY SECTORS EXT
    with open(dev, 'r') as fd:
        if fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio)) != 0:
            return None  # fcntl failed!
    if checkSense(sense, debug) is None:
        return None
    return sense


def sectorRead(dev, start, count):
    sense = ctypes.c_buffer(64)
    buf = ctypes.c_buffer(count * 512)
    sgio = prepareSgio(0x24, 0, count, start, SG_DXFER_FROM_DEV, sense, buf)  # READ SECTORS EXT
    with open(dev, 'r') as fd:
        if fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio)) != 0:
            return None  # fcntl failed!
    if checkSense(sense, debug) is None:
        return None
    return sense, buf


def sectorWrite(dev, start, count, buf):
    sense = ctypes.c_buffer(64)
    sgio = prepareSgio(0x34, 0, count, start, SG_DXFER_TO_DEV, sense, buf)  # WRITE SECTORS EXT
    with open(dev, 'r') as fd:
        if fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio)) != 0:
            return None  # fcntl failed!
    if checkSense(sense, debug) is None:
        return None
    return sense


def smartReadValues(dev):
    sense = ctypes.c_buffer(64)
    buf = ctypes.c_buffer(512)
    sgio = prepareSgio(0xb0, 0xd0, 1, 0xc24f00, SG_DXFER_FROM_DEV, sense, buf)  # SMART READ VALUES
    with open(dev, 'r') as fd:
        if fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio)) != 0:
            return None  # fcntl failed!
    if checkSense(sense, debug) is None:
        return None
    return sense, buf


def smartReadThresholds(dev):
    sense = ctypes.c_buffer(64)
    buf = ctypes.c_buffer(512)
    sgio = prepareSgio(0xb0, 0xd1, 1, 0xc24f00, SG_DXFER_FROM_DEV, sense, buf)  # SMART READ THRESHOLDS
    with open(dev, 'r') as fd:
        if fcntl.ioctl(fd, SG_IO, ctypes.addressof(sgio)) != 0:
            return None  # fcntl failed!
    if checkSense(sense, debug) is None:
        return None
    return sense, buf
