import yaml

# Use safe_load to avoid arbitrary code execution from untrusted YAML.
# Plain yaml.load() with the default Loader can construct arbitrary Python
# objects, which is a remote code execution risk if config.yml is ever
# supplied by an untrusted source.
config = yaml.safe_load(open('config.yml'))

print(config['mode'])
