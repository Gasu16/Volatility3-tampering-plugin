import datetime
import logging
import os
import json
import codecs
import contextlib

from typing import Any, Generator, List, Tuple
from volatility3.framework import automagic, objects, constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.framework.symbols import intermed
from volatility3.framework.renderers import TreeGrid, conversion, format_hints
#from volatility3.plugins import timeliner
from volatility3.plugins.windows.registry import *

#from volatility3.plugins.windows.registry import hivelist
from volatility3.plugins.windows.registry import printkey
#from volatility3.framework.layers.registry import RegistryHive, RegistryFormatException

vollog = logging.getLogger(__name__)

class Tampering(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel', architectures = ["Intel32", "Intel64"]),
                    #requirements.PluginRequirement(
                    #    name = 'printkey',
                    #    plugin = printkey,
                    #    version = (1, 1, 0)
                    #)
                ]
    def print_tampering_keys(cls): # Static Keys for tampering took from Windows registry
        #return [
        #    printkey.Printkey._printkey_iterator(hive="Microsoft\\Windows Defender\\Features") # Boh da capire
        #]
        print(f"Ce l'ho fattaaaaa")
        
    def run(self):
        #filter_func = printkey.PrintKey._printkey_iterator(self, self.config.get('hive', None))
        #filter_func = printkey.PrintKey._printkey_iterator(self, self.config.get('hive', None))
        #filter_func = printkey.PrintKey._printkey_iterator("\\REGISTRY\\MACHINE\\SYSTEM","\\REGISTRY\\MACHINE\\SYSTEM")
        kernel = self.context.modules[self.config['kernel']]
        #printkey.PrintKey._printkey_iterator(filter_func, "Microsoft\\Windows Defender\\Features"
        return renderers.TreeGrid([
                                   ("Key", str),
                                   ("Name", str)],
                                   #generator=filter_func)
                                   self._generator())
                                   #self._generator("\\REGISTRY\\MACHINE\\SYSTEM"))
    def _generator(self):
        print(f"hello world, I'm in the _generator func right now")
        self.print_tampering_keys()
        #for key in keys:
        #    yield ([0, (key)])
                       #key.ImageFileName.cast("string", max_length = key.ImageFileName.vol.count, errors = 'replace')))