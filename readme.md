# Url-Machine
An attempt to detect (and learn) malicious URL paths using fuzzy logic

## Requirements
- `fuzzywuzzy` package for fuzzy logic

## How to use
Run from the command line and give the first argument as the path, e.g. `urlmachine.py "index.py?action=dosomething"`.

## Planned functionality
- Taking into account checking how popular a path is, instead of how strong the matches are out of the known trusted
- Other more suitable and more effective self-learning methods?
- Attempting to navigate to the path specified, or any urls contained within the path for further assessment
