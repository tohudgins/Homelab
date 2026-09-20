# Homelab control — thin wrapper over scripts/lab.sh. Run `make help`.
# (Inline `;` recipes so no hard tabs are required.)
PROFILE ?= soc
NAME    ?= clean

.PHONY: help status up down stop converge snapshot restore profiles dashboards

help: ; @printf 'Homelab control (VMware Fusion + Ansible)\n\n  make status              VM power states\n  make up PROFILE=soc      start a run profile: networking|ad|soc|soc-ops|attack|vulnscan|services\n  make down                suspend all running VMs\n  make stop                clean poweroff of all running VMs\n  make converge            ansible-playbook site.yml (converge the whole lab)\n  make snapshot NAME=clean snapshot every running VM\n  make restore NAME=clean  revert VMs to a snapshot\n  make profiles            list run profiles and their VMs\n  make dashboards          open SSH tunnels to every lab web UI, one command\n'

status:     ; @scripts/lab.sh status
up:         ; @scripts/lab.sh up $(PROFILE)
down:       ; @scripts/lab.sh suspend
stop:       ; @scripts/lab.sh stop
converge:   ; @scripts/lab.sh converge
snapshot:   ; @scripts/lab.sh snapshot $(NAME)
restore:    ; @scripts/lab.sh restore $(NAME)
profiles:   ; @scripts/lab.sh profiles
dashboards: ; @scripts/dashboards.sh
