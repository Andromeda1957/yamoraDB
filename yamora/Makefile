CC ?= cc
PYTHON ?= python3
CPPFLAGS ?=
CPPFLAGS += -Isrc
CFLAGS ?= -std=c17 -O2 -Wall -Wextra -Wpedantic -Werror
LDLIBS ?= -pthread
YAML_CFLAGS ?= $(shell pkg-config --cflags yaml-0.1)
YAML_LDLIBS ?= $(shell pkg-config --libs yaml-0.1)
TLS_CFLAGS ?= $(shell pkg-config --cflags openssl)
TLS_LDLIBS ?= $(shell pkg-config --libs openssl)
SANITIZER_CC ?= clang
FUZZ_CC ?= afl-clang-fast
FUZZ_CFLAGS ?= -std=c17 -O1 -g -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -fno-omit-frame-pointer
FUZZ_LDLIBS ?= -pthread -fsanitize=address,undefined
DOTNET ?= dotnet
TSC ?= $(CURDIR)/../node_modules/.bin/tsc
NODE_TYPE_ROOTS ?= $(CURDIR)/../node_modules/@types

BUILD_DIR ?= build
TARGET := $(BUILD_DIR)/yamora
SESSION2_TARGET := $(BUILD_DIR)/yamora-session2
# Conformance fixtures require the exact daemon and its pre-launch digest.
NATIVE_TEST_ENV = YAMLDB_BUILD_DIR='$(abspath $(BUILD_DIR))' \
 YAMORA_TEST_BINARY='$(abspath $(TARGET))' \
 YAMORA_CONFORMANCE_SHA256="$$("$(PYTHON)" -c 'import hashlib, sys; f = open(sys.argv[1], "rb"); print(hashlib.file_digest(f, "sha256").hexdigest())' '$(abspath $(TARGET))')" \
 PYTHONPATH='$(CURDIR)/..'
LEGACY_TARGET := $(BUILD_DIR)/yamldb
LIMIT_TARGET := $(BUILD_DIR)/yamora-small-limits
FAULT_TARGET := $(BUILD_DIR)/yamora-fault-fsync
BINARY_FAULT_TARGET := $(BUILD_DIR)/yamora-binary-runtime-faults
OIDC_FAULT_TARGET := $(BUILD_DIR)/yamora-oidc-access-faults
SCHEMA_FAULT_TARGET := $(BUILD_DIR)/yamora-schema-faults
SCHEMA_API_TARGET := $(BUILD_DIR)/schema-policy-api
SCHEMA_CLUSTER_TARGET := $(BUILD_DIR)/schema-policy-cluster
BRANCH_HISTORY_TARGET := $(BUILD_DIR)/branch-history
FUZZ_HTTP_TARGET := $(BUILD_DIR)/fuzz-http-request
FUZZ_DOCUMENT_TARGET := $(BUILD_DIR)/fuzz-document
FUZZ_ENGINE_TARGET := $(BUILD_DIR)/fuzz-engine
FUZZ_JOURNAL_TARGET := $(BUILD_DIR)/fuzz-journal
LIB_SOURCE := src/disk.c src/retention_gate.c src/disk_checkpoint.c src/disk_tree.c src/disk_log.c src/disk_changes.c src/disk_replica.c src/disk_documents.c src/disk_source.c src/disk_source_value.c src/disk_history.c src/disk_history_validate.c src/disk_history_copy.c src/disk_branch.c src/disk_branch_api.c src/disk_indexes.c src/disk_query.c src/disk_api.c src/disk_bulk.c src/disk_compact.c src/aggregate.c src/disk_aggregate.c \
 src/binary.c src/binary_value.c src/snapshot.c src/snapshot_batch.c src/store.c src/compression.c \
 src/geo.c src/geo_cover.c src/disk_geo.c \
 src/value.c src/patch.c src/query.c src/query_regex.c src/indexes.c src/index_partial.c src/index_ttl.c src/journal.c src/document_api.c src/text.c src/disk_search.c src/disk_index_build.c src/disk_index_jobs.c \
 src/retention_terminal.c src/storage_budget.c src/consensus/receipt_retention.c src/disk_schema_barrier.c src/disk_schema_activation.c src/disk_schema_recovery.c src/disk_policy_api.c \
 src/schema/policy_catalog.c src/schema/policy_profile.c src/schema/shape_compile.c src/schema/shape_check.c \
 src/aggregate_keys.c src/aggregate_spill.c \
 src/schema/policy_store.c src/schema/policy_receipt.c src/schema/policy_admission.c \
 src/sharding/routing.c src/sharding/control.c src/sharding/native.c src/sharding/router.c \
 src/sharding/aggregate.c src/sharding/cursor.c src/sharding/service_apply.c \
 src/consensus/index_jobs.c src/consensus/replica.c
# Runtime access document and its replicated command (consensus prepare uses it).
LIB_SOURCE += src/security/access_state.c src/security/access_store.c
TLS_SOURCE := src/transport/tls.c src/transport/change_stream.c src/transport/binary_frame.c src/transport/binary_message.c src/transport/binary_session.c
SHARDING_SOURCE := src/sharding/service.c src/transport/shard_rpc.c
SECURITY_SOURCE := src/security/access.c src/security/oidc.c src/security/oidc_json.c
SECURITY_SOURCE += src/security/field_policy.c src/security/field_policy_query.c
SECURITY_SOURCE += src/security/field_response.c src/security/access_identity.c src/security/audit_client.c src/security/audit_codec.c src/security/audit_helper_codec.c src/security/audit_dispatch.c src/security/identity.c src/security/envelope.c src/security/key_provider.c src/security/storage_image.c src/security/storage_config.c
SECURITY_SOURCE += src/security/access_admin.c
AUDIT_HELPER_TARGET := $(BUILD_DIR)/yamora-audit-helper
AUDIT_HELPER_SOURCE := $(addprefix src/security/,audit.c audit_codec.c audit_helper_codec.c audit_custody.c audit_client.c audit_helper.c audit_helper_main.c)
# Native vector indexes and POST /v1/vector-search (docs/vector-search.md).
LIB_SOURCE += src/vector.c src/disk_vector.c
APPLICATION_SOURCE := $(addprefix src/consensus/,application.c application_policy.c branch.c)
CONSENSUS_SOURCE := $(APPLICATION_SOURCE) $(addprefix src/consensus/,raft.c raft_store.c backup.c session2_hooks.c retention_birth.c retention_session_record.c retention_session_owner.c journal_scope.c journal_namespace.c journal_dependencies.c journal_census.c journal_protection.c journal_copy.c journal_publish.c journal_compact.c wire.c rpc.c member.c read.c runtime.c application_validate.c application_copy.c application_archive.c application_retire.c archive_retention.c application_reference.c application_admission.c application_workspace.c application_compact.c application_worker.c snapshot.c snapshot_store.c snapshot_receive.c snapshot_send.c snapshot_restore.c recovery.c capture.c cluster.c cluster_receive.c checkpointer.c compactor.c config.c)
CONSENSUS_SOURCE += src/retention_terminal_capture.c
SOURCE := src/daemon.c src/index_ttl_runtime.c $(LIB_SOURCE) $(TLS_SOURCE) $(SHARDING_SOURCE) $(SECURITY_SOURCE) $(CONSENSUS_SOURCE)
HEADERS := $(wildcard src/*.h src/transport/*.h src/sharding/*.h src/security/*.h src/consensus/*.h src/schema/*.h)
SCHEMA_OBJECTS := $(patsubst %.c,$(BUILD_DIR)/schema-objects/%.o,$(SOURCE))
SCHEMA_SUPPORT := $(filter-out $(BUILD_DIR)/schema-objects/src/daemon.o,$(SCHEMA_OBJECTS))
SCHEMA_TEST_ENV = YAMORA_BRANCH_HISTORY_HARNESS='$(abspath $(BRANCH_HISTORY_TARGET))' \
 YAMORA_SCHEMA_API_HARNESS='$(abspath $(SCHEMA_API_TARGET))' \
 YAMORA_SCHEMA_CLUSTER_HARNESS='$(abspath $(SCHEMA_CLUSTER_TARGET))' \
 YAMORA_SCHEMA_OBJECT_DIR='$(abspath $(BUILD_DIR))/schema-objects/src' \
 YAMORA_SCHEMA_TEST_BINARY='$(abspath $(SCHEMA_FAULT_TARGET))' \
 YAMORA_SCHEMA_CONFORMANCE_SHA256="$$("$(PYTHON)" -c 'import hashlib, sys; f = open(sys.argv[1], "rb"); print(hashlib.file_digest(f, "sha256").hexdigest())' '$(abspath $(SCHEMA_FAULT_TARGET))')"
FUZZ_HEADERS := $(wildcard fuzz/*.h)
PREFIX ?= /usr/local

.PHONY: all test gitops-test go-test node-test java-test ruby-test rust-test cpp-test php-test csharp-test drivers-test sanitizer-test fuzz-build clean install

all: $(TARGET) $(LEGACY_TARGET) $(AUDIT_HELPER_TARGET)

$(AUDIT_HELPER_TARGET): $(AUDIT_HELPER_SOURCE) $(HEADERS) Makefile
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(TLS_CFLAGS) $(CFLAGS) $(AUDIT_HELPER_SOURCE) -o $@ $(LDLIBS) $(TLS_LDLIBS)

# Development runserver reuses the ignored build until a build input changes;
# this Makefile is one, since its flags shape the binary (owner, 2026-10-26).
$(TARGET): $(SOURCE) $(HEADERS) Makefile
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

$(LEGACY_TARGET): $(TARGET)
	cp $(TARGET) $(LEGACY_TARGET)

# Instrumentation is confined to this qualification artifact. Production builds
# retain the header's inline no-ops and never consult fault-control files.
$(SESSION2_TARGET): $(SOURCE) $(HEADERS) Makefile
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) $(CFLAGS) -DYD_RAFT_SESSION2_TEST_HOOKS $(SOURCE) -o $@ $(LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

# Small geo candidate limits let tests reach the per-query work bounds.
GEO_LIMIT_FLAGS := -DYD_GEO_NEAR_CANDIDATE_LIMIT=64 -DYD_GEO_REGION_CANDIDATE_LIMIT=64
$(LIMIT_TARGET): $(SOURCE) $(HEADERS)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) $(CFLAGS) -DYAMLDB_SNAPSHOT_BYTES_LIMIT=8192 $(GEO_LIMIT_FLAGS) $(SOURCE) -o $(LIMIT_TARGET) $(LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

$(FAULT_TARGET): $(SOURCE) $(HEADERS) tests/fault_fsync.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) $(CFLAGS) $(SOURCE) tests/fault_fsync.c -Wl,--wrap=fsync -o $(FAULT_TARGET) $(LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

# One real production object closure serves both schema artifacts. Faults are
# enabled only in these test objects, never in the ordinary daemon target.
$(BUILD_DIR)/schema-objects/%.o: %.c $(HEADERS)
	mkdir -p $(@D)
	$(CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) $(CFLAGS) -Isrc -DYD_DISK_TEST_FAULTS -ffunction-sections -fdata-sections -c $< -o $@

$(SCHEMA_FAULT_TARGET): $(SCHEMA_OBJECTS) $(BUILD_DIR)/schema-objects/tests/fault_fsync.o
	$(CC) $(CFLAGS) $^ -Wl,--gc-sections,--wrap=fsync -o $@ $(LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

$(SCHEMA_API_TARGET): $(SCHEMA_SUPPORT) $(BUILD_DIR)/schema-objects/tests/schema_policy_api_harness.o
	$(CC) $(CFLAGS) $^ -Wl,--gc-sections -o $@ $(LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

$(SCHEMA_CLUSTER_TARGET): $(SCHEMA_SUPPORT) $(BUILD_DIR)/schema-objects/tests/schema_policy_cluster_harness.o
	$(CC) $(CFLAGS) $^ -Wl,--gc-sections -o $@ $(LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

$(BRANCH_HISTORY_TARGET): $(SCHEMA_SUPPORT) $(BUILD_DIR)/schema-objects/tests/branch_history_harness.o
	$(CC) $(CFLAGS) $^ -Wl,--gc-sections -o $@ $(LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

$(BINARY_FAULT_TARGET): $(SOURCE) $(HEADERS) tests/binary_runtime_faults.c tests/certificate_access_faults.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) $(CFLAGS) $(SOURCE) tests/binary_runtime_faults.c tests/certificate_access_faults.c \
		-Wl,--wrap=yd_disk_api_request -Wl,--wrap=yd_raft_cluster_write \
		-Wl,--wrap=yd_connection_read_step -Wl,--wrap=yd_raft_cluster_storage -Wl,--wrap=yd_disk_view \
		-Wl,--wrap=yd_binary_runtime_start_with_identity \
		-o $@ $(LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

$(OIDC_FAULT_TARGET): $(SOURCE) $(HEADERS) tests/oidc_access_faults.c
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) $(CFLAGS) $(SOURCE) tests/oidc_access_faults.c \
		-Wl,--wrap=time -Wl,--wrap=yd_oidc_verify \
		-o $@ $(LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

test: $(TARGET) $(SESSION2_TARGET) $(LIMIT_TARGET) $(FAULT_TARGET) $(BINARY_FAULT_TARGET) $(OIDC_FAULT_TARGET) $(SCHEMA_FAULT_TARGET) $(SCHEMA_API_TARGET) $(SCHEMA_CLUSTER_TARGET) $(BRANCH_HISTORY_TARGET)
	YD_PC_TSAN=1 $(NATIVE_TEST_ENV) $(SCHEMA_TEST_ENV) "$(PYTHON)" -m unittest discover -s tests -p 'test_*.py'
	$(MAKE) gitops-test

gitops-test: $(TARGET)
	YAMORA_TEST_BINARY='$(abspath $(TARGET))' PYTHONPATH='$(CURDIR)/..' "$(PYTHON)" -m unittest discover -s gitops/tests -t .. -p 'test_*.py'

# The driver uses only Go's standard library. Its tests launch this native daemon
# on an OS-allocated port and keep generated files under the caller's TMPDIR.
go-test: $(TARGET)
	cd drivers/go && YAMORA_TEST_BINARY='$(abspath $(TARGET))' go test -race ./...

# Each driver gate uses the same freshly built daemon. Callers supply an owned
# disk-backed TMPDIR; build outputs stay under BUILD_DIR. Runtime/toolchain
# provisioning is separate from the production daemon installation.
node-test: $(TARGET)
	$(TSC) --project drivers/node/tsconfig.json --typeRoots '$(NODE_TYPE_ROOTS)'
	YAMORA_TEST_BINARY='$(abspath $(TARGET))' node --test drivers/node/tests/*.test.js

java-test: $(TARGET)
	"$(PYTHON)" -m unittest discover -s drivers/java/tests -p 'test_*.py'
	sh drivers/java/tests/run.sh '$(abspath $(TARGET))'

ruby-test: $(TARGET)
	YAMORA_TEST_BINARY='$(abspath $(TARGET))' ruby drivers/ruby/tests/run.rb

rust-test: $(TARGET)
	cd drivers/rust && cargo fmt --check
	cd drivers/rust && CARGO_TARGET_DIR='$(abspath $(BUILD_DIR))/rust-driver' cargo clippy --offline --locked --all-targets -- -D warnings
	cd drivers/rust && CARGO_TARGET_DIR='$(abspath $(BUILD_DIR))/rust-driver' cargo build --offline --locked --example raw
	cd drivers/rust && CARGO_TARGET_DIR='$(abspath $(BUILD_DIR))/rust-driver' \
		YAMORA_TEST_BINARY='$(abspath $(TARGET))' cargo test --offline --locked --all-targets -- --test-threads=1
	cd drivers/rust && CARGO_TARGET_DIR='$(abspath $(BUILD_DIR))/rust-driver' \
		YAMORA_TEST_BINARY='$(abspath $(TARGET))' "$(PYTHON)" tests/prove_binary_guards.py
	cd drivers/rust && CARGO_TARGET_DIR='$(abspath $(BUILD_DIR))/rust-conformance' \
		cargo test --offline --locked --manifest-path conformance/Cargo.toml --all-targets -- --test-threads=1

cpp-test: $(TARGET)
	cmake -S drivers/cpp -B '$(abspath $(BUILD_DIR))/cpp-driver' -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON
	cmake --build '$(abspath $(BUILD_DIR))/cpp-driver' -j2
	YAMORA_TEST_BINARY='$(abspath $(TARGET))' ctest --test-dir '$(abspath $(BUILD_DIR))/cpp-driver' --output-on-failure --no-tests=error

php-test: $(TARGET)
	"$(PYTHON)" drivers/php/tests/test_driver.py --binary '$(abspath $(TARGET))'

csharp-test: $(TARGET)
	DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
		DOTNET_GENERATE_ASPNET_CERTIFICATE=false DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true \
		DOTNET_CLI_HOME='$(abspath $(BUILD_DIR))/dotnet-home' NUGET_PACKAGES='$(abspath $(BUILD_DIR))/nuget' \
		$(DOTNET) build drivers/csharp/tests/Tests.csproj -c Release \
		--artifacts-path '$(abspath $(BUILD_DIR))/csharp-driver' --configfile drivers/csharp/NuGet.Config
	DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1 \
		DOTNET_GENERATE_ASPNET_CERTIFICATE=false DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE=true \
		DOTNET_CLI_HOME='$(abspath $(BUILD_DIR))/dotnet-home' NUGET_PACKAGES='$(abspath $(BUILD_DIR))/nuget' \
		YAMORA_TEST_BINARY='$(abspath $(TARGET))' $(DOTNET) run --project drivers/csharp/tests/Tests.csproj \
		-c Release --no-build --artifacts-path '$(abspath $(BUILD_DIR))/csharp-driver'
	"$(PYTHON)" drivers/csharp/tests/prove_binary_guards.py \
		--dotnet "$$(command -v $(DOTNET))" --binary '$(abspath $(TARGET))'

drivers-test: go-test node-test java-test ruby-test rust-test cpp-test php-test csharp-test

sanitizer-test:
	$(MAKE) clean
	$(MAKE) \
		CC='$(SANITIZER_CC)' \
		CFLAGS='-std=c17 -O1 -g -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer' \
		LDLIBS='-pthread -fsanitize=address,undefined' \
		all $(SESSION2_TARGET) $(LIMIT_TARGET) $(FAULT_TARGET) $(BINARY_FAULT_TARGET) $(OIDC_FAULT_TARGET) $(SCHEMA_FAULT_TARGET) $(SCHEMA_API_TARGET) $(SCHEMA_CLUSTER_TARGET) $(BRANCH_HISTORY_TARGET)
	ASAN_OPTIONS='detect_leaks=1:halt_on_error=1' \
	UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' \
	$(NATIVE_TEST_ENV) $(SCHEMA_TEST_ENV) \
	"$(PYTHON)" -m unittest discover -s tests -p 'test_*.py'
	ASAN_OPTIONS='detect_leaks=1:halt_on_error=1' \
	UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' $(MAKE) gitops-test

fuzz-build: $(FUZZ_HTTP_TARGET) $(FUZZ_DOCUMENT_TARGET) $(FUZZ_ENGINE_TARGET) $(FUZZ_JOURNAL_TARGET)

$(FUZZ_HTTP_TARGET): fuzz/http_request_fuzz.c $(SOURCE) $(HEADERS) $(FUZZ_HEADERS)
	mkdir -p $(BUILD_DIR)
	$(FUZZ_CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) $(FUZZ_CFLAGS) \
		fuzz/http_request_fuzz.c src/index_ttl_runtime.c $(LIB_SOURCE) $(TLS_SOURCE) $(SHARDING_SOURCE) $(SECURITY_SOURCE) $(CONSENSUS_SOURCE) \
		-o $(FUZZ_HTTP_TARGET) $(FUZZ_LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

$(FUZZ_DOCUMENT_TARGET): fuzz/document_fuzz.c $(LIB_SOURCE) $(HEADERS)
	mkdir -p $(BUILD_DIR)
	$(FUZZ_CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) $(FUZZ_CFLAGS) \
		fuzz/document_fuzz.c $(LIB_SOURCE) \
		-o $(FUZZ_DOCUMENT_TARGET) $(FUZZ_LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

$(FUZZ_ENGINE_TARGET): fuzz/engine_fuzz.c $(LIB_SOURCE) $(HEADERS)
	mkdir -p $(BUILD_DIR)
	$(FUZZ_CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) $(FUZZ_CFLAGS) \
		fuzz/engine_fuzz.c $(LIB_SOURCE) \
		-o $(FUZZ_ENGINE_TARGET) $(FUZZ_LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

$(FUZZ_JOURNAL_TARGET): fuzz/journal_fuzz.c $(LIB_SOURCE) $(HEADERS) $(FUZZ_HEADERS)
	mkdir -p $(BUILD_DIR)
	$(FUZZ_CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) $(FUZZ_CFLAGS) \
		fuzz/journal_fuzz.c $(LIB_SOURCE) \
		-o $(FUZZ_JOURNAL_TARGET) $(FUZZ_LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

install: $(TARGET) $(LEGACY_TARGET) $(AUDIT_HELPER_TARGET)
	install -d '$(DESTDIR)$(PREFIX)/bin'
	install -m 0755 $(TARGET) '$(DESTDIR)$(PREFIX)/bin/yamora'
	install -m 0755 $(TARGET) '$(DESTDIR)$(PREFIX)/bin/yamldb'
	install -m 0755 $(AUDIT_HELPER_TARGET) '$(DESTDIR)$(PREFIX)/bin/yamora-audit-helper'
	install -d '$(DESTDIR)$(PREFIX)/share/licenses/yamora'
	install -m 0644 LICENSE UNICODE-LICENSE.txt '$(DESTDIR)$(PREFIX)/share/licenses/yamora/'

clean:
	@if [ "$${ANDROMEDA_TASK_CONTAINER:-}" = 1 ] \
	    && [ -n "$${ANDROMEDA_REPOSITORY:-}" ] \
	    && [ '$(CURDIR)' = "$${ANDROMEDA_REPOSITORY:-}/yamora" ] \
	    && [ '$(abspath $(BUILD_DIR))' = '$(CURDIR)/build' ]; then \
	    "$(PYTHON)" '$(CURDIR)/../tools/shared/clean_build_output.py' 'yamora'; \
	else \
	    if [ -d '$(BUILD_DIR)' ]; then rm -r -- '$(BUILD_DIR)'; fi; \
	fi


# Optional focused binary decoder/round-trip fuzzing; normal builds need no fuzzer.
$(BUILD_DIR)/fuzz-binary: tests/binary_fuzz_harness.c $(LIB_SOURCE) $(HEADERS)
	mkdir -p $(BUILD_DIR)
	$(SANITIZER_CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) -std=c17 -O1 -g \
		-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
		tests/binary_fuzz_harness.c $(LIB_SOURCE) -o $@ -pthread $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

# Checksummed page framing and cursor traversal, including hostile child graphs.
$(BUILD_DIR)/fuzz-disk: tests/disk_fuzz_harness.c src/disk.c src/retention_gate.c src/disk_tree.c src/disk_log.c src/disk_history.c $(HEADERS)
	mkdir -p $(BUILD_DIR)
	$(SANITIZER_CC) $(CPPFLAGS) $(TLS_CFLAGS) -std=c17 -O1 -g -Wall -Wextra -Wpedantic -Werror \
		-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
		tests/disk_fuzz_harness.c src/disk.c src/retention_gate.c src/disk_tree.c src/disk_log.c src/disk_history.c -o $@ -pthread $(TLS_LDLIBS)

# Fuzz checksummed commit frames and the bounded change-feed decoder.
$(BUILD_DIR)/fuzz-changes: tests/disk_changes_fuzz_harness.c $(LIB_SOURCE) $(HEADERS)
	mkdir -p $(BUILD_DIR)
	$(SANITIZER_CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) -std=c17 -O1 -g \
		-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
		tests/disk_changes_fuzz_harness.c $(LIB_SOURCE) -o $@ -pthread $(TLS_LDLIBS) $(YAML_LDLIBS) -lm

# Opt-in durable scale benchmark; normal tests never ingest a million records.
$(BUILD_DIR)/disk-benchmark: tests/disk_benchmark.c $(LIB_SOURCE) $(HEADERS)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(TLS_CFLAGS) $(YAML_CFLAGS) $(CFLAGS) tests/disk_benchmark.c $(LIB_SOURCE) \
		-o $@ $(LDLIBS) $(TLS_LDLIBS) $(YAML_LDLIBS) -lm
