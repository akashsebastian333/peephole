import yaml

config = yaml.load(open('config.yml'))
print(config['mode'])
