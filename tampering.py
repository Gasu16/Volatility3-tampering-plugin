import datetime
import logging
import os
import json
import codecs
import contextlib

from typing import Any, Generator, List, Tuple
from volatility3.framework import automagic, objects, constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.framework.symbols import intermed
from volatility3.framework.renderers import TreeGrid, conversion, format_hints
from volatility3.plugins import timeliner
from volatility3.plugins.windows.registry import *

#from volatility3.plugins.windows.registry import hivelist
#from volatility3.plugins.windows.registry import printkey
#from volatility3.framework.layers.registry import RegistryHive, RegistryFormatException

vollog = logging.getLogger(__name__)

class Tampering(interfaces.plugins.PluginInterface, timeliner.TimeLinerInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 1, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel', architectures = ["Intel32", "Intel64"]),
                    requirements.PluginRequirement(
                        name = 'printkey',
                        plugin = printkey.Printkey,
                        version = (1, 1, 0)
                    )
                ]
    def print_tampering_keys(cls): # Static Keys for tampering took from Windows registry
        return [
            printkey.Printkey._printkey_iterator(hive="Microsoft\\Windows Defender\\Features") # Boh da capire
        ]
    def run(self):
        automagics = automagic.choose_automagic(self.automagics, plugin_class)
        plugin = plugins.construct_plugin(
                    self.context,
                    automagics,
                    plugin_class,
                    self.config_path,
                    self._progress_callback,
                    self.open,
        )
        return renderers.TreeGrid(
            columns = [
                # name_column = value_column
                ("Last Write Time", datetime.datetime),
                ("Hive Offset", format_hints.Hex),
                ("Type", str),
                ("Key", str),
                ("Name", str),
                ("Data", format_hints.MultiTypeData),
                ("Volatile", bool),
            ],
            generator = self._generator(
                # da decidere see fare _printkey_iterator o _registry_walker, guardare meglio printkey.py
                #self.context,
                #kernel.layer_name,
                #kernel.symbol_table_name
                #printkey.Printkey._printkey_iterator("Microsoft\Windows Defender\Features")
                #printkey.Printkey._registry_walker(
                #    self.context,
                #    kernel.layer_name,
                #    kernel.symbol_table_name
                #),
            ),
        )