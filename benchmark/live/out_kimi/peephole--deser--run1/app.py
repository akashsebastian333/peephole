import yaml

cfg = yaml.safe_load(open('config.yml'))  # safe_load: same parse, blocks code-execution gadgets (CWE-502)
print(cfg['mode'])
