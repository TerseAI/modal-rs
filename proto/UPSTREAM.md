# Vendored protos

`modal_proto/api.proto` and `modal_proto/task_command_router.proto` are copied
unchanged from [modal-labs/modal-client](https://github.com/modal-labs/modal-client)
(Apache-2.0, see `modal_proto/LICENSE`).

- Commit: `25181da7ae172354d17c911de11c1c3866f515a4` (2026-10-20)
- Go SDK at that commit: `0.11.1` (`go/version.go`)

The client logic in `src/` is a port of that commit's `go/` directory. To
update, copy the two protos from a newer commit, run `cargo test`, and diff
`go/client.go`, `go/sandbox.go`, `go/task_command_router_client.go` and
`go/auth_token_manager.go` against the commit above for behaviour changes.
