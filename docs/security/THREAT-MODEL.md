# ARTEX-Galactus threat model

Version: 2026-11-27. Assets: signing and encryption keys, operator sessions, PostgreSQL records, campaign files and evidence, tool credentials, archives and authorized target scope. Principals: operator, privileged server, future sandbox broker, Docker Engine, planner, worker, agent-launched processes, MCP services, LLM providers and external targets. Target content, scanner output, MCP responses and imported files are untrusted. A future broker and its Engine access would be a separate high-trust boundary; neither is implemented in the running ARTEX service.

## Abuse paths

1. Browser script or cross-origin request misuses a session through browser storage, URL transport or incomplete CSRF controls.
2. Untrusted tool output instructs a model to expand scope, read secrets or approve persistence. Only server-side authorization may decide those actions.
   One confirmed instance was `delete_assets_by_host`: an Auto agent tool could hard-delete root and child assets from the global library while carrying only task attribution. The local guard makes that legacy tool deny every call and moves the same operation to an authenticated operator API with an exact host confirmation. Skill, custom-tool, MCP and other platform mutations still require a separate authorization review; this change does not establish a general model-to-control-plane boundary.
3. A worker sharing identity, home, writable filesystem or namespace with another campaign reads or alters that campaign's state.
4. A privileged server validates a path, then follows a changed parent or link during a later operation.
5. A child process reaches PostgreSQL, management services or an unauthorized target without passing the application-level target parser.
6. Mutable files change during upload, archive or evidence staging, so approved bytes differ from stored bytes.
7. Exhaustion blocks the control plane or discards partial evidence.

## Required invariants

Operators alone grant effective execution and network scope. Campaign-private state is isolated during concurrent and sequential execution. Privileged filesystem actions remain confined under path races. Model text never grants capabilities. Session secrets do not travel through URLs or model-visible logs. Archive and evidence identity binds to bounded, immutable bytes. Unsupported isolation configurations fail closed. These are design targets, not current-state claims.
