#!/bin/bash -eu

go get github.com/AdamKorcz/go-118-fuzz-build/testing

compile_native_go_fuzzer github.com/Totative/go-avscan FuzzParseReply fuzz_parse_reply
compile_native_go_fuzzer github.com/Totative/go-avscan FuzzSplitCommand fuzz_split_command
