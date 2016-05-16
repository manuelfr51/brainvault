
def load_diceware(filename = None):
	dict = {}
	with open('diceware.wordlist.asc' if filename is None else filename, 'r') as diceware:
		lines = diceware.readlines()
		for line in lines:
			pair = line.strip().split('\t')
			if len(pair) == 2 and pair[0].isdigit() and len(pair[0]) == 5:
				dict[pair[0]] = pair[1]
	return dict

def to_string(number, dict):
	words = []
	stripped_number = number.lower().replace(' ', '')
	if len(stripped_number) % 5 != 0:
		raise Exception('One or more numbers are not 5 digit numbers')
	for segment_index in range(len(stripped_number) / 5):
		segment = stripped_number[segment_index *  5 : segment_index *  5 + 5]
		try:
			words.append(dict[segment])
		except KeyError:
			raise KeyError('{} is not a valid diceware word'.format(segment))
	return reduce(lambda word, res: word + ' ' + res, words, '')[1:]
