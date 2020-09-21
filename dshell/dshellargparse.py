"""
This argument parser is almost identical to the Python standard argparse.
This one adds a function to automatically add plugin-specific arguments.
"""

import argparse

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
