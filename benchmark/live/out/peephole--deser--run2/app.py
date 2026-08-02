import yaml

cfg = yaml.safe_load(open('config.yml'))
print(cfg['mode'])
