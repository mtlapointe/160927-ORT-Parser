import struct
import bitstring
import collections
import csv
import progressbar
import os
import binascii
import pandas as pd

import packet_formats


EXPORT_DIR = os.path.abspath(os.path.join(os.path.dirname('__file__'),
                                          'export'))
RAWDATA_DIR = os.path.abspath(os.path.join(os.path.dirname('__file__'),
                                           'rawdata'))


def read_boxcar_file(fname):
    """Read and clean-up data from specified Boxcar file.
    Returns list of [timestamp, packet id, packet hex string]"""
    df = pd.DataFrame(columns=['datetime', 'pid', 'packet_str'])

    print 'Loading Boxcar Data.'
    # pbar = progressbar.ProgressBar(maxval=get_file_len(fname)).start()

    data = []
    with open(fname) as datafile:
        j = 0
        for i, line in enumerate(datafile):
            # pbar.update(i)
            line_parsed = line.split('|')
            datetime = line_parsed[0][:-2]
            packet_str = line_parsed[4][1:-1]
            if len(packet_str) != 128:
                continue
            pid_word = '0x' + packet_str[16:20]  # word containing PID
            pid = int(pid_word, 16) & 2047  # mask PID from word
            if pid != 0:
                data += [[datetime, hex(pid), packet_str]]
                j += 1

    # pbar.finish()
    print 'Loading {}. Lines loaded: {}'.format(fname, j)

    return pd.DataFrame(data, columns=['datetime', 'pid', 'packet_str'])


def filter_boxcar_data(data, packet_list):
    """ Filter boxcar data for only packet IDs listed.
    Returns filtered data.
    """
    filtered_data = []

    for row in data:
        pid = row[1]
        if pid in get_iterable(packet_list):
            filtered_data += [row]

    print 'Filtering Complete. Filtered line count: ' + \
        str(int(len(filtered_data)))

    return filtered_data


def parse_packet_str(packet_str, packet_format):
    """ Parses packet hex string into list according to specified
    format definition.
    Returns list with parsed information.
    """
    packet_bs = bitstring.ConstBitStream('0x' + packet_str)
    packet_parsed = []

    for param_type in packet_format.itervalues():
        if param_type == 'float:16':
            float_int = half_to_float(packet_bs.read('uint:16'))
            float_str = struct.pack('I', float_int)
            val = struct.unpack('f', float_str)[0]
        elif param_type == 'text:352':
            val = text_from_bits(packet_bs.read('bin:352'))
        else:
            val = packet_bs.read(param_type)

        packet_parsed.append(val)

    return packet_parsed


def parse_packet_list(packets, packet_format):
    """ Takes a list of packets from box car file and parses them to
    specified format definition.
    Returns list of [timestamp, parsed data...] including header row.
    """
    parsed_data = []

    print 'Parsing Data.'
    pbar = progressbar.ProgressBar(maxval=len(packets)).start()

    header_line = ['datetime']
    for header in packet_format.iterkeys():
        header_line.append(header)
    parsed_data += [header_line]

    for i, row in enumerate(packets):
        packet_line = [row[0]]  # get date
        packet_line.extend(parse_packet_str(row[2], packet_format))
        parsed_data.append(packet_line)
        pbar.update(i+1)

    pbar.finish()
    print 'Parsing Data Complete.'

    return parsed_data


def parse_packet_list_pd(boxcar_df, pid, packet_format):
    """ Takes a list of packets from box car file and parses them to
    specified format definition.
    Returns list of [timestamp, parsed data...] including header row.
    """
    parsed_data = []

    filtered_df = boxcar_df[boxcar_df['pid'].isin([pid])]

    print 'Parsing Data.'
    pbar = progressbar.ProgressBar(maxval=len(boxcar_df)).start()

    header_line = ['datetime']
    for header in packet_format.iterkeys():
        header_line.append(header)
    parsed_data += [header_line]

    for i, row in filtered_df.iterrows():
        packet_line = [row['datetime']]  # get date
        packet_line.extend(parse_packet_str(row['packet_str'], packet_format))
        parsed_data.append(packet_line)
        pbar.update(i+1)

    pbar.finish()
    print 'Parsing Data Complete.'

    return parsed_data


def output_to_csv(data, outfile='output.csv'):
    """ Outputs list of data to CSV file
    """
    filepath = os.path.join(EXPORT_DIR, outfile)

    with open(filepath, 'wb') as myfile:
        wr = csv.writer(myfile, quoting=csv.QUOTE_ALL)
        for line in data:
            wr.writerow(line)


# HELPER FUNCTIONS


def half_to_float(h):
    # code from http://bit.ly/2dwmW78
    s = int((h >> 15) & 0x00000001)    # sign
    e = int((h >> 10) & 0x0000001f)    # exponent
    f = int(h & 0x000003ff)            # fraction

    if e == 0:
        if f == 0:
            return int(s << 31)
        else:
            while not (f & 0x00000400):
                f <<= 1
                e -= 1
            e += 1
            f &= ~0x00000400
            # print s, e, f
    elif e == 31:
        if f == 0:
            return int((s << 31) | 0x7f800000)
        else:
            return int((s << 31) | 0x7f800000 | (f << 13))

    e = e + (127 - 15)
    f = f << 13

    return int((s << 31) | (e << 23) | f)


def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return int2bytes(n).decode(encoding, errors)


def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))


def get_iterable(x):
    if isinstance(x, collections.Iterable):
        return x
    else:
        return (x,)


def get_file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1


# SCRIPT FUNCTIONS


def load_ort_data():
    file_list = [
        '20160927_1218_1330_ROSA_ORT_DATA.dat',
        '20160927_1330_1430_ROSA_ORT_DATA.dat',
        '20160927_1430_1530_ROSA_ORT_DATA.dat',
        '20160927_1530_1630_ROSA_ORT_DATA.dat',
        '20160927_1630_1730_ROSA_ORT_DATA.dat',
        '20160927_1730_1831_ROSA_ORT_DATA.dat']

    df_list = []
    for file in file_list:
        df_list.append(read_boxcar_file(os.path.join(RAWDATA_DIR, file)))

    return pd.concat(df_list).reset_index(drop=True)


def process_mcb2_data():

    all_data = load_ort_data()

    # rows = filter_boxcar_data(all_data, '0x407')
    data = parse_packet_list_pd(all_data, '0x407',
                                packet_formats.MCB_PACKET_DEF)

    output_to_csv(data, 'mcb2_data_pd.csv')


def process_pcu_data():

    all_data = read_boxcar_file('rawdata/ROSA_Boxcar.txt')

    rows = filter_boxcar_data(all_data, '0x403')
    data = parse_packet_list(rows, packet_formats.PCU_PACKET_DEF)

    output_to_csv(data, 'pcu_data.csv')

def process_evr_data():

    all_data = read_boxcar_file('rawdata/ROSA_Boxcar.txt')

    rows = filter_boxcar_data(all_data, '0x402')
    data = parse_packet_list(rows, packet_formats.EVR_PACKET_DEF)

    output_to_csv(data, 'evr_data.csv')


def process_iv_data():

    all_data = read_boxcar_file('rawdata/ROSA_Boxcar.txt')

    rows = filter_boxcar_data(all_data, '0x409')[170000:]
    data = parse_packet_list(rows, packet_formats.IV_PACKET_DEF)

    output_to_csv(data, 'iv_data.csv')


def mcb_dataframe():

    all_data = read_boxcar_file('rawdata/ROSA_Boxcar.txt')

    rows = filter_boxcar_data(all_data, '0x407')
    mcb_data = parse_packet_list(rows, packet_formats.MCB_PACKET_DEF)

    rows = filter_boxcar_data(all_data, '0x402')
    evr_data = parse_packet_list(rows, packet_formats.EVR_PACKET_DEF)

    mcb_df = pd.DataFrame(mcb_data[1:], columns=mcb_data[0])
    evr_df = pd.DataFrame(evr_data[1:], columns=evr_data[0])

    return pd.concat([mcb_df, evr_df]).sort(columns='datetime')


