# Homelab control — thin wrapper over scripts/lab.sh. Run `make help`.
# (Inline `;` recipes so no hard tabs are required.)
PROFILE ?= soc
NAME    ?= clean
PLAY    ?= site.yml
MODE    ?= capstone
ARGS    ?=

.PHONY: help status up down stop converge snapshot restore profiles dashboards attack backup-pull

help: ; @printf 'Homelab control (VMware Fusion + Ansible)\n\n  make status              VM power states\n  make up PROFILE=soc      start a run profile: networking|ad|soc|soc-ops|attack|vulnscan|services\n  make down                suspend all running VMs\n  make stop                clean poweroff of all running VMs\n  make converge            ansible-playbook site.yml (whole lab); PLAY=misp.yml etc. for one play\n  make snapshot NAME=clean snapshot every running VM\n  make restore NAME=clean  revert VMs to a snapshot\n  make profiles            list run profiles and their VMs\n  make dashboards          open SSH tunnels to every lab web UI, one command\n  make attack MODE=capstone|ad-validate  run a simulation with creds pulled from scripts/.lab-secrets (ARGS=--verify etc.)\n  make backup-pull         pull siem-01/misp-01 backups onto this Mac (off the VM disk they live on)\n\nNote: converge (site.yml) = core lab incl. osquery + SCA. PLAY=full.yml adds Velociraptor, MISP and IRIS\n(needs misp-01 up and the Velociraptor binaries staged) — the from-scratch rebuild path.\n'

status:     ; @scripts/lab.sh status
up:         ; @scripts/lab.sh up $(PROFILE)
down:       ; @scripts/lab.sh suspend
stop:       ; @scripts/lab.sh stop
converge:   ; @scripts/lab.sh converge $(PLAY)
snapshot:   ; @scripts/lab.sh snapshot $(NAME)
restore:    ; @scripts/lab.sh restore $(NAME)
profiles:   ; @scripts/lab.sh profiles
dashboards: ; @scripts/dashboards.sh
attack:     ; @scripts/run-attack.sh $(MODE) $(ARGS)
backup-pull: ; @scripts/pull-backups.sh
