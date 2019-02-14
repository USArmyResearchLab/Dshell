default: all

all: rc dshell

dshell: rc initpy pydoc

rc:
	# Generating .dshellrc and dshell files
	python $(PWD)/bin/generate-dshellrc.py $(PWD)
	chmod 755 $(PWD)/dshell
	chmod 755 $(PWD)/dshell-decode
	chmod 755 $(PWD)/bin/decode.py
	ln -s $(PWD)/bin/decode.py $(PWD)/bin/decode

initpy:
	find $(PWD)/decoders -type d -not -path \*.svn\* -print -exec touch {}/__init__.py \;

pydoc:
	(cd $(PWD)/doc && ./generate-doc.sh $(PWD) )

clean: clean_pyc clean_ln

distclean: clean clean_py clean_pydoc clean_rc

clean_rc:
	rm -fv $(PWD)/dshell
	rm -fv $(PWD)/dshell-decode
	rm -fv $(PWD)/.dshellrc

clean_ln:
	rm -fv $(PWD)/bin/decode

clean_py:
	find $(PWD)/decoders -name '__init__.py' -exec rm -v {} \;

clean_pyc:
	find $(PWD)/decoders -name '*.pyc' -exec rm -v {} \;
	find $(PWD)/lib -name '*.pyc' -exec rm -v {} \;

clean_pydoc:
	find $(PWD)/doc -name '*.htm*' -exec rm -v {} \;
