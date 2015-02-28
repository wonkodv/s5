
tags: *.py */*.py */*/*.py */*/*/*.py
	ctags --python-kinds=-i -R -o $@ ./

