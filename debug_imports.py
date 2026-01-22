
import sys
import os
import importlib
import pkgutil

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src"))

def import_submodules(package, recursive=True):
    if isinstance(package, str):
        package = importlib.import_module(package)
    results = {}
    for loader, name, is_pkg in pkgutil.walk_packages(package.__path__):
        if name.startswith('_'):
            continue
        full_name = package.__name__ + '.' + name
        print(f"Importing {full_name}...")
        try:
            module = importlib.import_module(full_name)
        except Exception as e:
            print(f"Error importing {full_name}: {e}")
            continue
        results[full_name] = module
        if recursive and is_pkg:
            results.update(import_submodules(full_name))
    return results

if __name__ == "__main__":
    print("Starting import...")
    modules = import_submodules("sentinelle.engines.mail.modules")
    print(f"Done. Imported {len(modules)} modules.")
