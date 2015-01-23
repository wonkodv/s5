
tags: *.py */*.py */*/*.py */*/*/*.py
	ctags --python-kinds=-i -R -o $@ ./

s5client:
	printf '#!/bin/bash\n\n#export S5_PASSWORD='UserKeyPassword'\nexport PYTHONPATH="$$PYTHONPATH":%s\nexec python3.4 -m s5.client "$$@"' $(PWD) > $@
	chmod +x $@

s5server:
	printf '#!/bin/bash\n\nexport PYTHONPATH="$$PYTHONPATH":%s\nexec python3.4 -m s5.server "$$@"' $(PWD) > $@
	chmod +x $@


