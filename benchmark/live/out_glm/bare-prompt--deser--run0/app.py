import yaml
import sys

CONFIG_PATH = 'config.yml'


def load_config(path):
    # Use safe_load to avoid arbitrary code execution from untrusted YAML.
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def main():
    try:
        config = load_config(CONFIG_PATH)
    except FileNotFoundError:
        print(f"Config file '{CONFIG_PATH}' not found", file=sys.stderr)
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing '{CONFIG_PATH}': {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(config, dict):
        print(f"Config must be a mapping, got {type(config).__name__}", file=sys.stderr)
        sys.exit(1)

    mode = config.get('mode')
    if mode is None:
        print("'mode' key not found in config", file=sys.stderr)
        sys.exit(1)

    print(mode)


if __name__ == '__main__':
    main()
