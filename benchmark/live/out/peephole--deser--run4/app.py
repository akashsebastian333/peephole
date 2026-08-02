import yaml

with open('config.yml') as f:
    config = yaml.safe_load(f)

print(config['mode'])
