import datetime
import logging
import os
import json
import codecs
import contextlib
import winreg
import win32evtlog
import xml.etree.ElementTree as ET
#from winevt import EventLog

from typing import Any, Generator, List, Tuple, Sequence, Iterable
from volatility3.framework import automagic, objects, constants, exceptions, interfaces, renderers, plugins
from volatility3.framework.configuration import requirements
#from volatility3.framework.interfaces import plugins
from volatility3.framework.layers import registry
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.framework.layers.registry import RegistryHive
from volatility3.framework.symbols import intermed
from volatility3.plugins.windows.registry import hivelist
from volatility3.framework.renderers import TreeGrid, conversion, format_hints
#from volatility3.plugins import timeliner
from volatility3.plugins.windows.registry import *
from volatility3.plugins.windows.registry import printkey
#from volatility3.framework.layers.registry import RegistryHive, RegistryFormatException

vollog = logging.getLogger(__name__)

roots_hives = [
    "HKEY_CLASSES_ROOT",
    "HKEY_CURRENT_USER",
    "HKEY_LOCAL_MACHINE", # Constant
    "HKEY_USERS",
    "HKEY_PERFORMANCE_DATA",
    "HKEY_CURRENT_CONFIG",
    "HKEY_DYN_DATA"
]

tampering_keys = [
    "SOFTWARE\\Microsoft\\Windows Defender", # DisableAntiSpyware; DisableAntiVirus; IsServiceRunning; PUAProtection;
    "SOFTWARE\\Microsoft\\Windows Defender\\Features", # TamperProtection; TamperProtectionSource; TPExclusions;
    "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", # Default; DpaDisabled;
    "SOFTWARE\\Microsoft\\Windows Defender\\Remediation\\Behavioral Network Blocks", # Default;
    "SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates" # SignatureLastUpdated; SignatureType; SignatureUpdateCount; SignatureUpdateLastAttempted; SignatureUpdatePending;
]

tampering_values = [
    "DisableAntiSpyware",
    "DisableAntiVirus",
    "IsServiceRunning",
    "PUAProtection",
    "TamperProtection",
    "TamperProtectionSource",
    "TPExclusions",
    "Default",
    "DpaDisabled",
    "SignatureLastUpdated",
    "SignatureType",
    "SignatureUpdateCount",
    "SignatureUpdateLastAttempted",
    "SignatureUpdatePending"
]

tampering_events_id = [
    "5004",
    "5007",
    "5008",
    "5010",
    "5012",
    "5013",
    "5100",
    "5101"
]

class Tampering(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel', architectures = ["Intel32", "Intel64"]),
                    requirements.PluginRequirement(
                        name = 'hivelist',
                        plugin = hivelist.HiveList,
                        version = (1, 0, 0)
                    )
                ]
    @classmethod
    def get_tampering_key(cls, root_hive, key, value):
        aReg = winreg.ConnectRegistry(None, root_hive)
        aKey = winreg.OpenKeyEx(aReg, key)
        sValue = winreg.QueryValueEx(aKey, value)
        eData = winreg.EnumValue(aKey, 0)
        l = []
        l.append(aReg)
        l.append(aKey)
        l.append(value)
        l.append(sValue)
        return l
    
    @classmethod
    def detect_tampering_attempts(cls):
        # https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
        # Event Viewer > Applications and Services Logs > Microsoft > Windows > Windows Defender > Operational
        # detect for events: 5004, 5007, 5008, 5010, 5012, 5013, 5100, 5101
        query_handle = win32evtlog.EvtQuery("C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx", win32evtlog.EvtQueryFilePath)       
        print(query_handle)
        read_count = 0
        while True:
            # read 100 records
            events = win32evtlog.EvtNext(query_handle, 10)
            read_count += len(events)
            # if there is no record break the loop
            if len(events) == 0:
                break
            for event in events:
                xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                # print(xml_content)

                # parse xml content
                xml = ET.fromstring(xml_content)
                # xml namespace, root element has a xmlns definition, so we have to use the namespace
                ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'

                event_id = xml.find(f'.//{ns}EventID').text
                level = xml.find(f'.//{ns}Level').text
                channel = xml.find(f'.//{ns}Channel').text
                execution = xml.find(f'.//{ns}Execution')
                process_id = execution.get('ProcessID')
                thread_id = execution.get('ThreadID')
                time_created = xml.find(f'.//{ns}TimeCreated').get('SystemTime')
                if event_id in tampering_events_id:
                    print(f'Time: {time_created}, Level: {level} Event Id: {event_id}, Channel: {channel}, Process Id: {process_id}, Thread Id: {thread_id}')
                user_data = xml.find(f'.//{ns}UserData')
                # user_data has possible any data
        print(f'Read {read_count} records')
        return
        
        
    def run(self):
        #kernel = self.context.modules[self.config['kernel']]
        #automagics = automagic.choose_automagic(automagic.available(self._context), hivelist.HiveList)
        #plugin = plugins.construct_plugin(self.context, automagics, hivelist.HiveList, self.config_path, self._progress_callback, self.open)
        #root_hive = winreg.HKEY_LOCAL_MACHINE
        
        return renderers.TreeGrid([
                                   ("Root Hive", str),
                                   ("Key", str),
                                   ("Data Name", str),
                                   ("Value", str)],
                                   self._generator(),
                                   )
    def _generator(self):
        root_hive = winreg.HKEY_LOCAL_MACHINE
        
        for _keys in tampering_keys:
            for _values in tampering_values:
                try:
                    args_ = self.get_tampering_key(root_hive, _keys, _values)
                    data_ = args_[2] # data value name
                    value_ = args_[3] # actual type value
                    yield (0, (str(root_hive), str(_keys), str(data_), str(value_[0])))
                except FileNotFoundError:
                    continue
        self.detect_tampering_attempts()