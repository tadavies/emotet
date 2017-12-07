import json
import argparse
import core.client as client

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-c", "--config", help="Client configuration filename")
	args = parser.parse_args()
	if not args.config:
		return
	
	clientConfig = json.load(open(args.config))
	c = client.client(clientConfig)
	c.start()


if __name__ == '__main__':
	main()
