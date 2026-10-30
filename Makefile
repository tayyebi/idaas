# idaas — make(1) build
#
# Targets that touch the host only read ./src, ./web, ./tests and write ./build.
# The Docker-facing targets (docker-*) exist so that nothing but Docker ever has
# to run on the host; the plain targets below are executed inside the image.

CC       ?= cc
CFLAGS   ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -D_POSIX_C_SOURCE=200809L
LDLIBS    = -lmicrohttpd -lpam -lcrypto -lcrypt -pthread

BUILD    := build
SRC      := src

SRCS     := $(wildcard $(SRC)/*.c)
OBJS     := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(SRCS))

# subset linked into the unit-test binary (no MHD, no main)
UNIT_SRCS := b64 rnd util log jsonw store jwt jwt_verify config users session accounts managed
UNIT_OBJS := $(addprefix $(BUILD)/,$(addsuffix .o,$(UNIT_SRCS)))
# test_pam.c has its own main() and is built by the separate pamtest target
UNIT_TEST_SRCS := $(filter-out tests/test_pam.c,$(wildcard tests/test_*.c))

.PHONY: all clean unit pamtest docker-build docker-test docker-smoke run update sync-users

all: $(BUILD)/idaas

$(BUILD):
	mkdir -p $@

# HTML pages are embedded into a generated header at build time
$(BUILD)/pages.h: web/login.html web/error.html web/choose.html scripts/embed.sh | $(BUILD)
	sh scripts/embed.sh $@ PAGE_LOGIN=web/login.html PAGE_ERROR=web/error.html PAGE_CHOOSE=web/choose.html

$(BUILD)/%.o: $(SRC)/%.c $(BUILD)/pages.h | $(BUILD)
	$(CC) $(CFLAGS) -I$(SRC) -I$(BUILD) -c $< -o $@

$(BUILD)/idaas: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

# unit tests (run inside the docker test stage; needs no PAM users)
unit: $(UNIT_OBJS) $(UNIT_TEST_SRCS) | $(BUILD)
	$(CC) $(CFLAGS) -I$(SRC) -I$(BUILD) -o $(BUILD)/unit $(UNIT_TEST_SRCS) $(UNIT_OBJS) -lcrypto -lcrypt -pthread
	$(BUILD)/unit

# PAM integration test; requires the fixture users created in the test image
pamtest: $(BUILD)/pam_auth.o $(BUILD)/util.o $(BUILD)/log.o $(BUILD)/jsonw.o $(BUILD)/b64.o tests/test_pam.c | $(BUILD)
	$(CC) $(CFLAGS) -I$(SRC) -I$(BUILD) -o $(BUILD)/pamtest tests/test_pam.c \
		$(BUILD)/pam_auth.o $(BUILD)/util.o $(BUILD)/log.o $(BUILD)/jsonw.o $(BUILD)/b64.o \
		-lpam -lcrypto -pthread
	$(BUILD)/pamtest

clean:
	rm -rf $(BUILD)

# ---- host-facing wrappers: everything below builds/runs only in Docker ----

IMAGE ?= idaas

docker-build:
	docker build -t $(IMAGE) .

docker-test:
	docker build --target test -t $(IMAGE)-test .

docker-smoke:
	sh scripts/smoke.sh

# compose pulls ghcr.io/<owner>/idaas:latest by default; IDAAS_IMAGE=... overrides
run:
	docker compose pull || true
	docker compose up -d

# force-refresh to the newest published image
update:
	docker compose pull
	docker compose up -d

# Snapshot /etc/{passwd,shadow,group} into ./data/etc (reads host /etc,
# writes only inside ./data). Needs root to read /etc/shadow.
sync-users:
	sh scripts/sync-users.sh
