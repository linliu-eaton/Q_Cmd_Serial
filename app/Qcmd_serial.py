import os
import configparser
import logging
import time
import re

import serial   # serial
from ctypes import *

__all__ = ["ser_q_cmd"]


# com
_COM_comPort = ''
_COM_baudRate = 2400
_COM_byteSize = 8
_COM_stopBit = 1
_COM_parity = 'N'

# qcmd
_QCMD_rspTimeoutSec = 2
_QCMD_cmdIntervalMs = 0
_QCMD_loopTimes = 1
_QCMD_enableChkRsp = True
_QCMD_cmdList = ''
_QCMD_rspList = ''

# logging
_LOG_enableLog = False
_LOG_logDir = ''

_CMD_LIST = []
_RSP_LIST = []
_COM_PORT = None

_RSP_REGEX_PREFIX = "regex:"


# log config --------------------------
def _log_init():
    if _LOG_enableLog is False:
        return

    log_file = os.path.join(_LOG_logDir, "ser_log.log")
    log_file_abs = os.path.abspath(log_file)
    print("Log file: " + str(log_file_abs))
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename=log_file_abs,
                        filemode='a')


def _log_debug(msg, *args, **kwargs):
    if _LOG_enableLog is False:
        return
    logging.debug(msg, *args, **kwargs)


def _log_info(msg, *args, **kwargs):
    if _LOG_enableLog is False:
        return
    logging.info(msg, *args, **kwargs)


def _log_warn(msg, *args, **kwargs):
    if _LOG_enableLog is False:
        return
    logging.warning(msg, *args, **kwargs)


def _log_critical(msg, *args, **kwargs):
    if _LOG_enableLog is False:
        return
    logging.critical(msg, *args, **kwargs)


# config parse --------------------------
def _show_config():
    print("_COM_comPort=" + str(_COM_comPort))
    print("_COM_baudRate=" + str(_COM_baudRate))
    print("_COM_byteSize=" + str(_COM_byteSize))
    print("_COM_stopBit=" + str(_COM_stopBit))
    print("_COM_parity=" + str(_COM_parity))
    print("_QCMD_rspTimeoutSec=" + str(_QCMD_rspTimeoutSec))
    print("_QCMD_cmdIntervalMs=" + str(_QCMD_cmdIntervalMs))
    print("_QCMD_loopTimes=" + str(_QCMD_loopTimes))
    print("_QCMD_enableChkRsp=" + str(_QCMD_enableChkRsp))
    print("_QCMD_cmdList=" + str(_QCMD_cmdList))
    print("_QCMD_rspList=" + str(_QCMD_rspList))
    print("_LOG_enableLog=" + str(_LOG_enableLog))
    print("_LOG_logDir=" + str(_LOG_logDir))

    _log_info("_COM_comPort=" + str(_COM_comPort))
    _log_info("_COM_baudRate=" + str(_COM_baudRate))
    _log_info("_COM_byteSize=" + str(_COM_byteSize))
    _log_info("_COM_stopBit=" + str(_COM_stopBit))
    _log_info("_COM_parity=" + str(_COM_parity))
    _log_info("_QCMD_rspTimeoutSec=" + str(_QCMD_rspTimeoutSec))
    _log_info("_QCMD_cmdIntervalMs=" + str(_QCMD_cmdIntervalMs))
    _log_info("_QCMD_loopTimes=" + str(_QCMD_loopTimes))
    _log_info("_QCMD_enableChkRsp=" + str(_QCMD_enableChkRsp))
    _log_info("_QCMD_cmdList=" + str(_QCMD_cmdList))
    _log_info("_QCMD_rspList=" + str(_QCMD_rspList))
    _log_info("_LOG_enableLog=" + str(_LOG_enableLog))
    _log_info("_LOG_logDir=" + str(_LOG_logDir))


def _config_parse():
    config_path = os.path.join(os.path.dirname(__file__), 'Qserial_config.ini')
    config = configparser.ConfigParser()
    config.read(config_path, encoding='utf-8')

    global _COM_comPort
    global _COM_baudRate
    global _COM_byteSize
    global _COM_stopBit
    global _COM_parity

    global _QCMD_rspTimeoutSec
    global _QCMD_cmdIntervalMs
    global _QCMD_loopTimes
    global _QCMD_enableChkRsp
    global _QCMD_cmdList
    global _QCMD_rspList

    global _LOG_enableLog
    global _LOG_logDir

    # com
    _COM_comPort = config.get('com', 'comPort')
    if _COM_comPort == '':
        raise Exception('Not config com port!')
    _COM_baudRate = config.getint('com', 'baudRate')
    _COM_byteSize  = config.getint('com', 'byteSize')
    _COM_stopBit = config.getint('com', 'stopBit')
    _COM_parity = config.get('com', 'parity')
    if _COM_parity == '':
        raise Exception('Not config com parity!')

    # qcmd
    _QCMD_rspTimeoutSec = config.getint('qcmd', 'rspTimeoutSec')
    _QCMD_cmdIntervalMs = config.getint('qcmd', 'cmdIntervalMs')
    _QCMD_loopTimes = config.getint('qcmd', 'loopTimes')
    _QCMD_enableChkRsp = config.getboolean('qcmd', 'enableChkRsp')
    _QCMD_cmdList = config.get('qcmd', 'cmdList')
    if _QCMD_cmdList == '':
        raise Exception('Not config commands!')
    _QCMD_rspList = config.get('qcmd', 'rspList')
    if (_QCMD_enableChkRsp is True) and (_QCMD_rspList == ''):
        raise Exception("Check response enabled but no response list configured!")

    # log
    _LOG_enableLog = config.getboolean('log', 'enableLog')
    _LOG_logDir = config.get('log', 'logDir')
    if (_LOG_enableLog is True) and (_LOG_logDir == ''):
        raise Exception("Log enabled but no log file configured!")
    valid_dir = (os.path.isdir(_LOG_logDir)) and (os.access(_LOG_logDir, os.W_OK))
    if (_LOG_enableLog is True) and (not valid_dir):
        raise Exception("Log enabled but log file is invalid!")
    print("Parse config file success......")

    if _LOG_enableLog:
        _log_init()
    _log_info("Parse config file success......")

    _show_config()


def _config_to_char_list(conf_str: str) -> list:
    """return type: [['Q', '1', ''\r], ['F', 'W', 'V', '\r']]"""
    conf_list = []
    conf_str = conf_str.strip()
    if conf_str == '':
        return conf_list

    cmd_lst = conf_str.split(',')
    for cmd in cmd_lst:
        lst = []
        cmd = cmd.strip()
        if cmd == '':
            conf_list.append(lst)
            continue
        for s in cmd:
            lst.append(ord(s))
        lst.append(0x0D)
        conf_list.append(lst)
    return conf_list


def _get_cmd_ascii_list():
    global _CMD_LIST
    _CMD_LIST = _config_to_char_list(_QCMD_cmdList)
    print("CMD_LIST:" + str(_CMD_LIST))
    _log_info("CMD_LIST:" + str(_CMD_LIST))


def _get_rsp_str_list():
    """result type: [''Q1\r, 'FWV\r']"""
    global _QCMD_rspList
    global _RSP_LIST

    conf_str = _QCMD_rspList
    conf_str = conf_str.strip()
    if conf_str == '':
        _RSP_LIST.append('')
    else:
        _RSP_LIST = conf_str.split(',')

    if (_QCMD_enableChkRsp is True) and (len(_CMD_LIST) != len(_RSP_LIST)):
        raise Exception('Unmatched command and response count!')
    print("RSP_LIST:" + str(_RSP_LIST))
    _log_info("RSP_LIST:" + str(_RSP_LIST))


# serial function ------------------------
def _open_port():
    global _COM_PORT
    _COM_PORT = serial.Serial(timeout=_QCMD_rspTimeoutSec)
    _COM_PORT.port = _COM_comPort
    _COM_PORT.baudrate = _COM_baudRate
    _COM_PORT.bytesize = _COM_byteSize
    _COM_PORT.stopbits = _COM_stopBit
    _COM_PORT.parity = _COM_parity
    _COM_PORT.open()
    if _COM_PORT.isOpen():
        print("Port " + str(_COM_comPort) + " open success!")
        _log_info("Port " + str(_COM_comPort) + " open success!")
    else:
        print(" Port" + str(_COM_comPort) + " open failed!")
        _log_info(" Port" + str(_COM_comPort) + " open failed!")


def _close_port():
    global _COM_PORT
    if _COM_PORT.isOpen():
        _COM_PORT.close()
    print("Serial port Closed!")
    _log_info("Serial port Closed!")


def _send_data(cmd: list):
    global _COM_PORT
    _COM_PORT.reset_output_buffer()
    _COM_PORT.reset_input_buffer()

    data = bytearray(cmd)
    buffer = create_string_buffer(len(data))
    for idx in range(len(data)):
        buffer[idx] = data[idx]
    rsp_len = _COM_PORT.write(buffer)
    return rsp_len


def _recv_rsp():
    global _COM_PORT
    rsp = _COM_PORT.read_until(expected="\r", size=None)   # type bytes
    if len(rsp) == 0:
        return ''
    rsp_str = ''
    for b in rsp:
        rsp_str += chr(b)
    return rsp_str


def _cmd_rsp_check(cmd: list, idx: int, result: str):
    if _QCMD_enableChkRsp is False:
        return

    if _RSP_LIST[idx] == '_':
        print(str(cmd) + "(idx:" + str(idx) + ")" + "rsp check Ignored!")
        _log_info(str(cmd) + "(idx:" + str(idx) + ")" + "rsp check Ignored!")
        return

    if len(result) <= 1:
        print(str(cmd) + "(idx:" + str(idx) + ")" + "rsp check Failed, blank response!")
        _log_info(str(cmd) + "(idx:" + str(idx) + ")" + "rsp check Failed, blank response!")
        return

    if result[-1] != '\r':
        print(str(cmd) + "(idx:" + str(idx) + ")" + "rsp check Failed, invalid rsp!")
        _log_info(str(cmd) + "(idx:" + str(idx) + ")" + "rsp check Failed, invalid rsp!")
        return

    result = result[:-1]

    if len(_RSP_LIST) < (idx + 1):
        print(str(cmd) + "(idx:" + str(idx) + ")" + "rsp check Failed, rsp config error!")
        _log_info(str(cmd) + "(idx:" + str(idx) + ")" + "rsp check Failed, rsp config error!")
        return

    # regex response check
    rsp_src = _RSP_LIST[idx]
    if rsp_src.startswith(_RSP_REGEX_PREFIX):
        rsp_patt = rsp_src[len(_RSP_REGEX_PREFIX):]
        if re.match(rsp_patt, result) is None:
            print(str(cmd) + "(idx:" + str(idx) + ") " + "rsp REGEX check Failed!")
            _log_info(str(cmd) + "(idx:" + str(idx) + ") " + "rsp REGEX check Failed!")
        else:
            print(str(cmd) + "(idx:" + str(idx) + ") " + "rsp REGEX check Succeed!")
            _log_info(str(cmd) + "(idx:" + str(idx) + ") " + "rsp REGEX check Succeed!")
        return

    # non-regex response check
    if _RSP_LIST[idx] != result:
        print(str(cmd) + "(idx:" + str(idx) + ")" + "rsp check Failed!")
        _log_info(str(cmd) + "(idx:" + str(idx) + ")" + "rsp check Failed!")
        return

    print(str(cmd) + "(idx:" + str(idx) + ")" + "rsp check Succeed!")
    _log_info(str(cmd) + "(idx:" + str(idx) + ")" + "rsp check Succeed!")


# serial Q command implementation
def ser_q_cmd():
    # config file
    try:
        _config_parse()
        _get_cmd_ascii_list()
        _get_rsp_str_list()
    except Exception as e:
        print("------Exception when parse config ", e)
        _log_info("------Exception when parse config ",  e)
        return

    # serial config
    try:
        _open_port()
        time.sleep(0.2)
    except Exception as e:
        print("------Exception when open port ", e)
        _log_info("------Exception when open port ",  e)
        _close_port()
        return
    print("serial communication begin......")
    _log_info("serial communication begin......")

    try:
        for loop in range(_QCMD_loopTimes):
            print("loop: " + str(loop + 1))
            _log_info("loop: " + str(loop + 1))
            for idx, cmd in enumerate(_CMD_LIST):
                if _QCMD_cmdIntervalMs > 0:
                    time.sleep(_QCMD_cmdIntervalMs/1000)
                try:
                    print("Send cmd: " + str(cmd))
                    _log_info("Send cmd: " + str(cmd))
                    _send_data(cmd)

                    result = _recv_rsp()
                    print("Recv response: " + str(result))
                    _log_info("Recv response: " + str(result))

                    _cmd_rsp_check(cmd, idx, result)
                except Exception as e:
                    print("------Exception when send ", str(cmd), e)
                    _log_info("------Exception when send ", str(cmd), e)

    except Exception as e:
        print("------Exception in loop: ", e)
        _log_info("------Exception in loop: ",  e)
    _close_port()


if __name__ == "__main__":
    ser_q_cmd()


