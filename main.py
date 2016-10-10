import packet_parser
import packet_formats
import pandas as pd


BOXCAR_FILE_LIST = (
    'rawdata/20160927_1218_1330_ROSA_ORT_DATA.dat',
    'rawdata/20160927_1330_1430_ROSA_ORT_DATA.dat',
    'rawdata/20160927_1430_1530_ROSA_ORT_DATA.dat',
    'rawdata/20160927_1530_1630_ROSA_ORT_DATA.dat',
    'rawdata/20160927_1630_1730_ROSA_ORT_DATA.dat',
    'rawdata/20160927_1730_1831_ROSA_ORT_DATA.dat')


# HELPER FUNCTIONS

def load_ort_boxcar_data():
    """ Returns DataFrame with all boxcar data from ORT test with timestamp,
        packet id, and packet hex string (aka boxcar format)
        Header:  datetime, pid, packet_str
    """

    data = packet_parser.read_boxcar_file(*BOXCAR_FILE_LIST)
    return pd.DataFrame(data, columns=['datetime', 'pid', 'packet_str'])


def process_boxcar_data(data, pid, pformat=None):
    """ Returns DataFrame of parsed data for specified packet id and format.
        Parse data according to appropriate packet format for that pid if none
        specified.
    """
    if pformat is None:
        pformat_map = packet_formats.packet_format_map
        pformat = getattr(packet_formats, pformat_map[pid])

    return packet_parser.process_boxcar_df(data, pid, pformat)


def csv_parsed_packet_list(pid_list):
    """ Create CSV files for specified packet types. Uses default pformats
        unless otherwise specified.
    """
    bc_data = load_ort_boxcar_data()

    for pid in pid_list:
        print 'Parsing Packet Id: {}'.format(pid)
        parsed_df = process_boxcar_data(bc_data, pid)
        parsed_df.to_csv('export/{}_parsed.csv'.format(pid))


def csv_parsed_packet_list_raw(pid_list):
    """ Create CSV files for specified packet types. Uses default pformats
        unless otherwise specified.
    """
    bc_data = load_ort_boxcar_data()
    raw_pformat = packet_formats.RAW_PACKET_DEF
    for pid in pid_list:
        print 'Parsing Packet Id: {}'.format(pid)
        parsed_df = process_boxcar_data(bc_data, pid, raw_pformat)
        parsed_df.to_csv('export/{}_parsed_raw.csv'.format(pid))


def add_evr_to_csv(pid_list):
    """ Opens CSV for specified packet id and adds EVRs
    """
    for pid in pid_list:
        df = pd.read_csv('export/{}_parsed.csv'.format(pid), index_col=0)
        evr_df = pd.read_csv('export/0x402_parsed.csv', index_col=0)

        # specify order of columns (and drop anything not wanted)
        cols = df.columns.insert(1, 'ascii_data')

        new_df = pd.concat([df, evr_df]) \
            .sort_values(by='datetime').reset_index(drop=True)

        new_df[cols].to_csv('export/{}_parsed_w_evr.csv'.format(pid))


def trim_packet_evr_csv_files():
    slice_list = {
        # SSD
        '0x404': [slice(17076, 17399)],
        # Cameras and experiment settings
        '0x405': [slice(4420, 5395), slice(15794, 18011)],
        # MCB 1 limit switches
        '0x406': [slice(4615, 4875)],
        # MCB 2 limit switches and motors
        '0x407': [slice(5015, 5175), slice(14896, 19403), slice(20469, 22418),
                  slice(22648, 27389)],
        # RTDs and Damper Voltage
        '0x408': [slice(20754, 22504), slice(24894, 25329)],
        # IV Sweep Data
        '0x409': [slice(173015, None)],
        # Accelerometer Data
        '0x411': [slice(180897, None)]
    }

    for pid, slices in slice_list.iteritems():
        csv_df = pd.read_csv('export/{}_parsed_w_evr.csv'.format(pid),
                             index_col=0)

        dfs = []
        for slc in slices:
            dfs.append(csv_df.iloc[slc])
        pd.concat(dfs).to_csv('export/{}_parsed_w_evr_trimmed.csv'
                              .format(pid))


# MAIN FUNCTIONS


def output_packet_id_list(pid_list):
    csv_parsed_packet_list(pid_list)
    add_evr_to_csv(pid_list)


def output_all_packet_ids():
    all_pids = packet_formats.packet_format_map.keys()
    output_packet_id_list(all_pids)


def output_all_packets_as_raw():
    all_pids = packet_formats.packet_format_map.keys()
    csv_parsed_packet_list_raw(all_pids)
