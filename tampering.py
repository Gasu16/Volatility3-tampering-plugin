import datetime
import logging
import os
import json
import codecs
import contextlib

from typing import Any, Generator, List, Tuple
from volatility3.framework import objects, constants, exceptions, interfaces, renderers
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
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel', architectures = ["Intel32", "Intel64"]),
                    requirements.PluginRequirement(
                        name = 'printkey',
                        plugin = printkey.Printkey,
                        version = (1, 1, 0)
                    )
                ]
    def run(self):
        return renderers.TreeGrid(
            columns = [
                # name_column = value_column
            ],
            generator = self.generator(
                # da decidere see fare _printkey_iterator o _registry_walker, guardare meglio printkey.py
                printkey.Printkey._printkey_iterator(
                    self.context,
                    kernel.layer_name,
                    kernel.symbol_table_name
                ),
            ),
        )