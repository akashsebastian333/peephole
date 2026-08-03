import yaml

cfg = yaml.safe_load(open('config.yml'))  # safe_load: yaml.load executes arbitrary objects (CWE-502)
print(cfg['mode'])
