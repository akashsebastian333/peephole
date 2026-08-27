import yaml

with open('config.yml') as f:
    config = yaml.load(f, Loader=yaml.FullLoader)
    print(config['mode'])
