import os
import subprocess
import sys

def install_plugins():
    """
    Finds and installs all plugins in the 'plugins' directory.
    """
    plugins_dir = "plugins"
    if not os.path.isdir(plugins_dir):
        print(f"Directory '{plugins_dir}' not found.")
        return

    for plugin_name in os.listdir(plugins_dir):
        plugin_path = os.path.join(plugins_dir, plugin_name)
        if os.path.isdir(plugin_path) and "pyproject.toml" in os.listdir(plugin_path):
            print(f"Installing plugin: {plugin_name}")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "-e", plugin_path]
                )
                print(f"Successfully installed {plugin_name}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to install {plugin_name}. Error: {e}")

if __name__ == "__main__":
    install_plugins()