import struct
import bitstring
import collections
import csv
import progressbar
import os
import binascii
import pandas as pd

import packet_formats


EXPORT_DIR = os.path.abspath(
    os.path.join(os.path.dirname('__file__'), 'export'))

RAWDATA_DIR = os.path.abspath(
    os.path.join(os.path.dirname('__file__'), 'rawdata'))


def read_boxcar_file(*fnames):
    """ Read and clean-up data from specified Boxcar file.
        Returns list of [timestamp, packet id, packet hex string]
    """
    data = []

    print 'Loading Boxcar Data.'

    # get length of all files in list, initialize pbar
    total_len = 0
    for f in get_iterable(fnames):
        total_len += get_file_len(f)
    pbar = progressbar.ProgressBar(maxval=total_len).start()

    progress = 0
    for fname in get_iterable(fnames):
        with open(fname) as f:
            for i, l in enumerate(f):
                pbar.update(i + progress)   # update progress bar
                s = l.split('|')            # split file by |
                datetime = s[0][:-2]        # trim excess space from datetime
                packet_str = s[4][1:-1]     # trim whitespace from packet_str
                if len(packet_str) != 128:  # ignore malformed packet_str
                    continue
                pid_word = '0x' + packet_str[16:20]    # word containing pid
                pid = int(pid_word, 16) & 2047    # mask packet id from word
                if pid != 0:    # add non-zero packet id's to data
                    data += [[datetime, hex(pid), packet_str]]
        progress += i   # update overall progress

    pbar.finish()
    print 'Loading Boxcar Data Complete. Lines loaded: {}'.format(len(data))

    return data


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
    """ Takes a list of packets in boxcar format and parses them to
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
    print 'Parsing Data Complete. Lines Parsed: {}'.format(i)

    return parsed_data


def process_boxcar_df(boxcar_df, pid, pformat):
    """ Parse DataFrame of Boxcar data into a new DataFrame.
        Takes packet id (pid) as hex string or list of strings
        and parses according to packet format (pformat)
        Returns parsed data frame
    """
    pid = get_iter_str_list(pid)

    # filter only specified packets
    # unpack to list of lists for parsing
    # sorta a hack job - maybe make this more efficient

    filtered_list = \
        boxcar_df[boxcar_df['pid'].isin(pid)].values.tolist()

    data = parse_packet_list(filtered_list, pformat)

    # data has header info in top row
    return pd.DataFrame(data[1:], columns=data[0])


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


def get_iter_str_list(x):
    # trick for py2/3 compatibility
    if 'basestring' not in globals():
        basestring = str
    if isinstance(x, basestring):
        return [x]
    return x


def get_file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1


# SCRIPT FUNCTIONS

def load_ort_boxcar_data():
    """ Returns DataFrame with all boxcar data from ORT test with timestamp,
        packet id, and packet hex string (aka boxcar format)
        Header:  datetime, pid, packet_str
    """
    file_list = (
        'rawdata/20160927_1218_1330_ROSA_ORT_DATA.dat',
        'rawdata/20160927_1330_1430_ROSA_ORT_DATA.dat',
        'rawdata/20160927_1430_1530_ROSA_ORT_DATA.dat',
        'rawdata/20160927_1530_1630_ROSA_ORT_DATA.dat',
        'rawdata/20160927_1630_1730_ROSA_ORT_DATA.dat',
        'rawdata/20160927_1730_1831_ROSA_ORT_DATA.dat')

    data = read_boxcar_file(*file_list)

    return pd.DataFrame(data, columns=['datetime', 'pid', 'packet_str'])


def process_boxcar_data(data, pid):
    """ Returns DataFrame of parsed data for specified packet id,
        parsed according to appropriate packet format for that pid
    """
    pformat = getattr(packet_formats, packet_formats.packet_format_map[pid])

    return process_boxcar_df(data, pid, pformat)


# DEMO FUNCTIONS

def parse_list(packets):
    bc_data = load_ort_boxcar_data()

    for pid in packets:
        print 'Parsing Packet Id: {}'.format(pid)

        parsed_df = process_boxcar_data(bc_data, pid)
        parsed_df.to_csv('export/{}_parsed.csv'.format(pid))


def parse_all_data():
    parse_list(packet_formats.packet_format_map.keys())


def add_evr_to_csv(pid):

    df = pd.read_csv('export/{}_parsed.csv'.format(pid), index_col=0)
    evr_df = pd.read_csv('export/0x402_parsed.csv', index_col=0)

    # specify order of columns (and drop anything not wanted)
    cols = df.columns.insert(1, 'ascii_data')

    new_df = pd.concat([df, evr_df]) \
        .sort_values(by='datetime').reset_index(drop=True)

    new_df[cols].to_csv('export/{}_parsed_w_evr.csv'.format(pid))
