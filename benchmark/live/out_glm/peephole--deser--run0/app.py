import yaml

config = yaml.load(open('config.yml'), Loader=yaml.SafeLoader)
print(config['mode'])
