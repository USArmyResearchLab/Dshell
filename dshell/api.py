"""
Dshell3 Python API
"""

import logging
import operator
from importlib import import_module

# TODO: Move get_plugins() here?
from .dshelllist import get_plugins


logger = logging.getLogger(__name__)


# TODO: Should this be renamed to "load_plugins()" since it actually imports the modules?
def get_plugin_information() -> dict:
    """
    Generates and returns a dictionary of plugins.
    :return: dictionary containing plugin name -> plugin module
    :raises ImportError: If a plugin could not be imported.
    """
    plugin_map = get_plugins()
    # Import ALL of the decoders and print info about them before exiting
    plugins = {}
    for name, module in sorted(plugin_map.items(), key=operator.itemgetter(1)):
        try:
            module = import_module(module)
            if not module.DshellPlugin:
                continue
            module = module.DshellPlugin()
            plugins[name] = module
        except Exception as e:
            raise ImportError(f"Could not load {repr(module)} with error: {e}")

    return plugins
