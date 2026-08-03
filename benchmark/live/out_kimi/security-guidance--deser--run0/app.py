import yaml

with open('config.yml') as f:
    config = yaml.safe_load(f)  # ponytail: yaml.load is unsafe deserialization (arbitrary code exec); safe_load is a drop-in

print(config['mode'])
