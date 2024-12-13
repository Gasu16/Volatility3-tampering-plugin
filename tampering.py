import datetime
import logging
import os
import json
import codecs
import contextlib
import winreg
import win32evtlog
import xml.etree.ElementTree as ET
import pdb

from typing import Any, Generator, List, Tuple, Sequence, Iterable
from volatility3.framework import automagic, objects, constants, exceptions, interfaces, renderers, plugins
from volatility3.framework.configuration import requirements
from volatility3.framework.layers.physical import BufferDataLayer
from volatility3.framework.layers.registry import RegistryHive, RegistryFormatException
from volatility3.framework.symbols import intermed
from volatility3.framework.renderers import TreeGrid, conversion, format_hints
from volatility3.framework.symbols.windows.extensions.registry import RegValueTypes
from volatility3.plugins.windows.registry import hivelist


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

new_tampering_keys = [
    # Forse dovrei dargli come key solo "Microsoft\\Windows Defender"
    "SOFTWARE\\Microsoft\\Windows Defender\\DisableAntiSpyware",
    "SOFTWARE\\Microsoft\\Windows Defender\\DisableAntiVirus",
    "SOFTWARE\\Microsoft\\Windows Defender\\IsServiceRunning",
    "SOFTWARE\\Microsoft\\Windows Defender\\PUAProtection",
    "SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtection",
    "SOFTWARE\\Microsoft\\Windows Defender\\Features\\TamperProtectionSource",
    "SOFTWARE\\Microsoft\\Windows Defender\\Features\\TPExclusions",
    "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\Default",
    "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DpaDisabled",
    "SOFTWARE\\Microsoft\\Windows Defender\\Remediation\\Behavioral Network Blocks\\Default",
    "SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates\\SignatureLastUpdated",
    "SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates\\SignatureType",
    "SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates\\SignatureUpdateCount",
    "SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates\\SignatureUpdateLastAttempted",
    "SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates\\SignatureUpdatePending"
]

tampering_events_files = [
    "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx",
    "C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-SENSE%4Operational.evtx"
]

tampering_events_id = [
    "5",
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
        from volatility3.plugins.windows.registry import hivelist
        return [requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel', architectures = ["Intel32", "Intel64"]),
                    requirements.PluginRequirement(
                        name = 'hivelist',
                        plugin = hivelist.HiveList,
                        version = (1, 0, 0)
                    ),
                     requirements.BooleanRequirement(
                        name="recurse",
                        description="Recurses through keys",
                        default=True,
                        optional=True,
                    ),
                ]
    @classmethod
    def get_tampering_key(cls, root_hive: RegistryHive, node_path: Sequence[objects.StructType] = None):
        node_path = [root_hive.get_node(root_hive.root_cell_offset)]
        print(node_path)
        return node_path
    
    @classmethod
    def get_keys(cls, hive: RegistryHive, node_path: Sequence[objects.StructType] = None, recurse: bool = True,) -> Iterable[Tuple[int, bool, datetime.datetime, str, bool, interfaces.objects.ObjectInterface]]:
        #def get_keys(cls, hive: RegistryHive, node_path: Sequence[objects.StructType] = None, recurse: bool = True)-> Generator[Tuple[int, Tuple], None, None]:
        if not node_path:
            node_path = [hive.get_node(hive.root_cell_offset)]
        if not isinstance(node_path, list) or len(node_path) < 1:
            vollog.warning("Hive walker was not passed a valid node_path (or None)")
            return None
        node = node_path[-1]
        key_path_items = [hive] + node_path[1:]
        key_path = "\\".join([k.get_name() for k in key_path_items])
        if node.vol.type_name.endswith(constants.BANG + "_CELL_DATA"):
            raise RegistryFormatException(
                hive.name, "Encountered _CELL_DATA instead of _CM_KEY_NODE"
            )
        last_write_time = conversion.wintime_to_datetime(node.LastWriteTime.QuadPart)
        for key_node in node.get_subkeys():
            result = (
                len(node_path),
                True,
                last_write_time,
                key_path,
                key_node.get_volatile(),
                key_node,
            )
            #print("\nquesto e' il result: ")
            #print(result)
            yield result
            
            if recurse:
                if key_node.vol.offset not in [x.vol.offset for x in node_path]:
                    try:
                        key_node.get_name()
                    except exceptions.InvalidAddressException as excp:
                        vollog.debug(excp)
                        continue
                        
                    yield from cls.get_keys(
                        hive, node_path + [key_node], recurse=recurse
                    )
        for value_node in node.get_values():
            result = (
                len(node_path),
                False,
                last_write_time,
                key_path,
                node.get_volatile(),
                value_node,
            )
            yield result
            
    def _printkey(self, hive: RegistryHive, node_path: Sequence[objects.StructType] = None, recurse: bool = True):
        for(
            depth,
            is_key,
            last_write_time,
            key_path,
            volatile,
            node,
        ) in self.get_keys(hive, node_path, recurse):
            if is_key:
                try:
                    key_node_name = node.get_name()
                except (
                    exceptions.InvalidAddressException,
                    RegistryFormatException,
                ) as excp:
                    vollog.debug(excp)
                    key_node_name = renderers.UnreadableValue()
                    
                last_write_time = conversion.wintime_to_datetime(node.LastWriteTime.QuadPart)
                yield (
                    depth,
                    (
                        last_write_time,
                        renderers.format_hints.Hex(hive.hive_offset),
                        "Key",
                        key_path,
                        key_node_name,
                        renderers.NotApplicableValue(),
                        volatile,
                    ),
                )
            else:
                try:
                    value_node_name = node.get_name() or "(Default)"
                except (
                    exceptions.InvalidAddressException,
                    RegistryFormatException,
                ) as excp:
                    vollog.debug(excp)
                    value_node_name = renderers.UnreadableValue()
                
                try:
                    value_type = RegValueTypes(node.Type).name
                except (
                    exceptions.InvalidAddressException,
                    RegistryFormatException,
                ) as excp:
                    vollog.debug(excp)
                    value_type = renderers.UnreadableValue()
                
                if isinstance(value_type, renderers.UnreadableValue):
                    vollog.debug("Couldn't read registry value type, so data is unreadable")
                    value_data: Union[interfaces.renderers.BaseAbsentValue, bytes] = (renderers.UnreadableValue())
                else:
                    try:
                        value_data = node.decode_data()
                        if isinstance(value_data, int):
                            value_data = format_hints.MultiTypeData(
                                value_data, encoding="utf-8"
                            )
                        elif RegValueTypes(node.Type) == RegValueTypes.REG_BINARY:
                            value_data = format_hints.MultiTypeData(
                                value_data, show_hex=True
                            )
                        elif RegValueTypes(node.Type) == RegValueTypes.REG_MULTI_SZ:
                            value_data = format_hints.MultiTypeData(
                                value_data, encoding="utf-16-le", split_nulls=True
                            )
                        else:
                            value_data = format_hints.MultiTypeData(
                                value_data, encoding="utf-16-le"
                            )
                    except (
                        ValueError,
                        exceptions.InvalidAddressException,
                        RegistryFormatException,
                    ) as excp:
                        vollog.debug(excp)
                        value_data = renderers.UnreadableValue()
                result = (
                    depth,
                    (
                        last_write_time,
                        renderers.format_hints.Hex(hive.hive_offset),
                        value_type,
                        key_path,
                        value_node_name,
                        value_data,
                        volatile,
                    ),
                )
                yield result

    def run(self):
        offset = self.config.get("offset", None)
        kernel = self.context.modules[self.config["kernel"]]
        
        return renderers.TreeGrid(
            [
                ("Last Write Time", datetime.datetime),
                ("Hive Offset", format_hints.Hex),
                ("Type", str),
                ("Key", str),
                ("Name", str),
                ("Data", format_hints.MultiTypeData),
                ("Volatile", bool),
            ],
            self._generator(
                kernel.layer_name,
                kernel.symbol_table_name,
                hive_offsets=None if offset is None else [offset],
                key=self.config.get("key", None),
                recurse=self.config.get("recurse", None),
            ),
        )

    def _generator(self, layer_name: str, symbol_table: str, hive_offsets: List[int] = None, key: str = None, recurse: bool = True,):
        #i = 0
        for hive in hivelist.HiveList.list_hives(
            self.context,
            self.config_path,
            layer_name = layer_name,
            symbol_table = symbol_table,
            hive_offsets = hive_offsets,
            ):
                #pdb.set_trace()
                try:
                    #if i < len(new_tampering_keys):
                        #key = new_tampering_keys[i]
                        #i += 1
                    key = "Microsoft\\Windows Defender"
                    #if key in new_tampering_keys:
                    if key is not None:
                        node_path = hive.get_key(key, return_list=True)
                    else:
                        node_path = [hive.get_node(hive.root_cell_offset)]
                    for x, y in self._printkey(hive, node_path, recurse=recurse):
                        yield (x - len(node_path), y)
                except (
                    exceptions.InvalidAddressException,
                    KeyError,
                    RegistryFormatException,
                ) as excp:
                    if isinstance(excp, KeyError):
                        vollog.debug(
                            f"key '{key}' not found in Hive at offset {hex(hive.hive_offset)}."
                        )
                    elif isinstance(excp, RegistryFormatException):
                        vollog.debug(excp)
                    elif isinstance(excp, exceptions.InvalidAddressException):
                        vollog.debug(
                            f"Invalid address identified in Hive: {hex(excp.invalid_address)}"
                        )
                    result = (
                        0,
                        (
                            renderers.UnreadableValue(),
                            format_hints.Hex(hive.hive_offset),
                            "Key",
                            f"{hive.get_name()}\\" + (key or ""),
                            renderers.UnreadableValue(),
                            renderers.UnreadableValue(),
                            renderers.UnreadableValue(),
                        ),
                    )
                    yield result