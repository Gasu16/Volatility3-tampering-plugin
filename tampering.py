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
    "HKEY_LOCAL_MACHINE",
    "HKEY_USERS",
    "HKEY_PERFORMANCE_DATA",
    "HKEY_CURRENT_CONFIG",
    "HKEY_DYN_DATA"
]

tampering_hives = []

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
        #get Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Features
        #aReg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        #aKey = winreg.OpenKey(aReg, r"SOFTWARE\\Microsoft\\Windows Defender\\Features")
        aReg = winreg.ConnectRegistry(None, root_hive)
        aKey = winreg.OpenKey(aReg, key)
        print(r"reading from %s" % aKey)
        sValue = winreg.QueryValueEx(aKey, value)
        qinfokey = winreg.QueryInfoKey(aKey)
        print(f"The key value is: ",sValue[0])
        print(f"Last modified: ",qinfokey[2])
        
    @classmethod
    def print_tampering_keys(self): # Static Keys for tampering took from Windows registry
        print(f"Ce l'ho fattaaaaa")
        
        
    def run(self):
        kernel = self.context.modules[self.config['kernel']]
        automagics = automagic.choose_automagic(automagic.available(self._context), hivelist.HiveList)
        plugin = plugins.construct_plugin(self.context, automagics, hivelist.HiveList, self.config_path, self._progress_callback, self.open)
        
        return renderers.TreeGrid([
                                   ("Root Hive", str),
                                   ("Key", str),
                                   ("Value", str)],
                                   self._generator(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows Defender\\Features", "TamperProtection"),
                                   )
    def _generator(self, root_hive, key, value):
        print(f"hello world, I'm in the _generator func right now")
        self.get_tampering_key(root_hive, key, value)