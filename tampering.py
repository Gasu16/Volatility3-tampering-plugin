import datetime
import logging
import os
import json
import codecs
import contextlib
import winreg

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

# tampering_ttps = []

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
        l = []
        aReg = winreg.ConnectRegistry(None, root_hive)
        aKey = winreg.OpenKeyEx(aReg, key)
        sValue = winreg.QueryValueEx(aKey, value)
        l.append(aReg)
        l.append(aKey)
        l.append(sValue)
        return l
        
    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        automagics = automagic.choose_automagic(automagic.available(self._context), hivelist.HiveList)
        plugin = plugins.construct_plugin(self.context, automagics, hivelist.HiveList, self.config_path, self._progress_callback, self.open)
        root_hive = winreg.HKEY_LOCAL_MACHINE
        
        return renderers.TreeGrid([
                                   ("Root Hive", str),
                                   ("Key", str),
                                   ("Value", str)],
                                   self._generator(),
                                   )
    def _generator(self):
        root_hive = winreg.HKEY_LOCAL_MACHINE
        for _keys in tampering_keys:
            for _values in tampering_values:
                try:
                    args_ = self.get_tampering_key(root_hive, _keys, _values)
                    value_ = args_[2] # extract value field from tuple
                    yield (0, (str(root_hive), str(_keys), str(value_[0])))
                except FileNotFoundError:
                    continue