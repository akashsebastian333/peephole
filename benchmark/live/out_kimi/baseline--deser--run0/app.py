import yaml

# ponytail: safe_load instead of unsafe yaml.load() — same one line, no arbitrary-object deserialization
config = yaml.safe_load(open('config.yml'))
print(config['mode'])
