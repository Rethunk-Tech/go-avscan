#!/bin/bash -eu

go get github.com/AdamKorcz/go-118-fuzz-build/testing@a70c2aa677fa43583571959478decabe02a96cd6 # v0.0.0-20250520111509-a70c2aa677fa

compile_native_go_fuzzer github.com/Totative/go-avscan FuzzParseReply fuzz_parse_reply
compile_native_go_fuzzer github.com/Totative/go-avscan FuzzSplitCommand fuzz_split_command
