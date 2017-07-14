# Run commands from here using the following syntax:
# make <target> arg1=foo arg2=bar arg3=baz

# default variables
limit = none
key = keys/$(env)/$(env)
tag = master
leg = all
datetime = $(shell date +%Y%m%d-%k%M%S)

default:
	@echo "A task must be specified"
	@echo ""
	@echo "  To install on a new OS instance: "
	@echo "      make install limit=<IP Address>"
	@echo ""

limit-check:
ifeq ("$(limit)", "none")
	$(error A 'limit' param must be specified for this command)
endif

# environment configuration
# -------------------------
install-idp:
	export ANSIBLE_HOST_KEY_CHECKING=False
	ansible-playbook -i inventories/main --limit $(limit) install_idp.yml -u user1 --sudo --ask-pass --ask-sudo-pass $(params)

install-ldap:
	export ANSIBLE_HOST_KEY_CHECKING=False
	ansible-playbook -i inventories/main --limit $(limit) install_ldap.yml -u user1 --sudo --ask-pass --ask-sudo-pass $(params)
