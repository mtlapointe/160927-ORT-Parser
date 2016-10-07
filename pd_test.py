import pandas as pd
import numpy as np
import math
import collections


### NOT FASTER #####
def load_boxcars_to_df(filelist):

    dfs = []
    for file in get_iterable(filelist):
        df = (pd.read_csv(file, sep='|', header=0,
                          usecols=[0, 4], names=['datetime', 'packet_str']))

        packet_int = df['packet_str'].apply(lambda x: int(x, 16))
        pid_shift = np.right_shift(packet_int, (512-80))
        pid_col = np.bitwise_and(pid_shift, int(math.pow(2, 11)-1))

        df['pid'] = pid_col
        dfs.append(df[df['pid'] > 0])

    return pd.concat(dfs).reset_index(drop=True)


def load_ort_df():
    file_list = [
        'rawdata/20160927_1218_1330_ROSA_ORT_DATA.dat',
        'rawdata/20160927_1330_1430_ROSA_ORT_DATA.dat',
        'rawdata/20160927_1430_1530_ROSA_ORT_DATA.dat',
        'rawdata/20160927_1530_1630_ROSA_ORT_DATA.dat',
        'rawdata/20160927_1630_1730_ROSA_ORT_DATA.dat',
        'rawdata/20160927_1730_1831_ROSA_ORT_DATA.dat']

    return load_boxcars_to_df(file_list)






def get_iterable(x):
    if isinstance(x, collections.Iterable):
        return x
    else:
        return (x,)
