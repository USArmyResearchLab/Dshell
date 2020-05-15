"""
This argument parser is almost identical to the Python standard argparse.
This one adds a function to automatically add plugin-specific arguments.
"""

import argparse


def custom_bytes(value):
    """
    Converts value strings for command lines that are suppose to be bytes.
    If value startswith "0x", value will be assumed to be a hex string.
    Otherwise data will be encoded with utf8
    """
    if isinstance(value, bytes):
        return value
    if value.startswith("0x"):
        try:
            return bytes.fromhex(value[2:])
        except ValueError:
            pass  # Wasn't hex after all, just treat as a utf8 string.
    return value.encode("utf8")


class DshellArgumentParser(argparse.ArgumentParser):

    def add_plugin_arguments(self, plugin_name, plugin_obj):
        """
        add_plugin_arguments(self, plugin_name, plugin_obj)

        Give it the name of the plugin and an instance of the plugin, and
        it will automatically create argument entries.
        """
        if plugin_obj.optiondict:
            group = '{} plugin options'.format(plugin_obj.name)
            group = self.add_argument_group(group)
            for argname, optargs in plugin_obj.optiondict.items():
                optname = "{}_{}".format(plugin_name, argname)
                data_type = optargs.get("type", None)
                if data_type and data_type == bytes:
                    optargs["type"] = custom_bytes
                    default = optargs.get("default", None)
                    if default is not None:
                        optargs["default"] = custom_bytes(default)
                group.add_argument("--" + optname, dest=optname, **optargs)

    def get_plugin_arguments(self, plugin_name, plugin_obj):
        """
        get_plugin_arguments(self, plugin_name, plugin_obj)

        Returns a list of argument names and the attributes they're associated
        with.

        e.g. --country_code for the "country" plugin ties to the "code" attr
             in the plugin object. Thus, the return would be
             [("country_code", "code"), ...]
        """
        args_and_attrs = []
        if plugin_obj.optiondict:
            for argname in plugin_obj.optiondict.keys():
                optname = "{}_{}".format(plugin_name, argname)
                args_and_attrs.append((optname, argname))
        return args_and_attrs
