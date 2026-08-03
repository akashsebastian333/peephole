import yaml

# ponytail: safe_load, not bare yaml.load — PyYAML>=6 requires a Loader anyway
# and full load can execute arbitrary code from config.yml
with open('config.yml') as f:
    config = yaml.safe_load(f)

print(config['mode'])
