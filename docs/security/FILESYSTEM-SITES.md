# Direct server filesystem sites

Source snapshot: commit `b9b2a7f`. This inventory records 203 direct `os` filesystem calls in production Go files under `server/`; tests are excluded. It is a starting list of privileged sites, not proof that every transitive filesystem action is safe. Callers using `os.Root`, `io.Copy`, `http.ServeFile`, archive helpers, third-party packages and database-backed paths need separate review.

| Source | Operation | Statement |
| --- | --- | --- |
| `server/ask_operator.go:204` | `os.Open` | `f, err := os.Open(path)` |
| `server/ask_operator.go:220` | `os.Mkdir` | `if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {` |
| `server/ask_operator.go:223` | `os.Lstat` | `if fi, err := os.Lstat(dir); err != nil \|\| !fi.IsDir() {` |
| `server/ask_operator.go:257` | `os.Lstat` | `st, err := os.Lstat(resolved)` |
| `server/ask_operator.go:278` | `os.OpenFile` | `out, err = os.OpenFile(filepath.Join(dir, name), os.O_WRONLY\|os.O_CREATE\|os.O_EXCL, 0o640)` |
| `server/auth.go:81` | `os.MkdirAll` | `if err := os.MkdirAll(keyDir, 0o700); err != nil {` |
| `server/auth.go:85` | `os.Stat` | `if _, err := os.Stat(path); os.IsNotExist(err) {` |
| `server/auth.go:90` | `os.ReadFile` | `data, err := os.ReadFile(path)` |
| `server/auth.go:126` | `os.ReadFile` | `data, err := os.ReadFile(src)` |
| `server/auth.go:137` | `os.Remove` | `if err := os.Remove(src); err != nil {` |
| `server/auth.go:148` | `os.OpenFile` | `f, err := os.OpenFile(path, os.O_WRONLY\|os.O_CREATE\|os.O_EXCL, 0o600)` |
| `server/auth.go:154` | `os.Remove` | `_ = os.Remove(path)` |
| `server/auth.go:158` | `os.Remove` | `_ = os.Remove(path)` |
| `server/chatupload.go:96` | `os.MkdirAll` | `if err := os.MkdirAll(dir, 0o755); err != nil {` |
| `server/chatupload.go:167` | `os.Lstat` | `_, err = os.Lstat(path)` |
| `server/conversations.go:235` | `os.RemoveAll` | `if err := os.RemoveAll(dir); err != nil {` |
| `server/customtool.go:507` | `os.MkdirAll` | `} else if err := os.MkdirAll(toolsDir, 0o755); err != nil {` |
| `server/customtool.go:510` | `os.CreateTemp` | `f, err := os.CreateTemp(toolsDir, key+"-*.py")` |
| `server/customtool.go:515` | `os.Remove` | `defer os.Remove(tmp)` |
| `server/customtool.go:667` | `os.ReadFile` | `if pem, err := os.ReadFile(caFile); err == nil {` |
| `server/execpriv_unix.go:77` | `os.MkdirAll` | `if err := os.MkdirAll(home, 0o700); err != nil {` |
| `server/execpriv_unix.go:80` | `os.Lstat` | `fi, err := os.Lstat(home)` |
| `server/execpriv_unix.go:87` | `os.Lchown` | `if err := os.Lchown(home, int(p.UID), int(p.GID)); err != nil {` |
| `server/execpriv_unix.go:90` | `os.Chmod` | `if err := os.Chmod(home, 0o700); err != nil {` |
| `server/execpriv_unix.go:111` | `os.Mkdir` | `if err := os.Mkdir(dir, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {` |
| `server/execpriv_unix.go:114` | `os.Lstat` | `fi, err := os.Lstat(dir)` |
| `server/execpriv_unix.go:121` | `os.Lchown` | `if err := os.Lchown(dir, 0, int(p.GID)); err != nil {` |
| `server/execpriv_unix.go:124` | `os.Chmod` | `if err := os.Chmod(dir, 0o750); err != nil {` |
| `server/execpriv_unix.go:147` | `os.Mkdir` | `if err := os.Mkdir(dir, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {` |
| `server/execpriv_unix.go:150` | `os.Lstat` | `fi, err := os.Lstat(dir)` |
| `server/execpriv_unix.go:155` | `os.Stat` | `parent, err := os.Stat(filepath.Dir(dir))` |
| `server/execpriv_unix.go:247` | `os.Chown` | `if err := os.Chown(path, -1, int(p.GID)); err != nil {` |
| `server/execpriv_unix.go:250` | `os.Chmod` | `return os.Chmod(path, 0o640)` |
| `server/execpriv_unix.go:306` | `os.Stat` | `if _, err := os.Stat(path); err == nil {` |
| `server/execpriv_unix.go:310` | `os.Chmod` | `if err := os.Chmod(path, 0o600); err != nil {` |
| `server/execpriv_unix.go:316` | `os.Stat` | `if _, err := os.Stat(configPath); err == nil {` |
| `server/execpriv_unix.go:321` | `os.Stat` | `if fi, err := os.Stat(configPath); err == nil && fi.Mode().Perm()&0o077 != 0 {` |
| `server/execpriv_unix.go:322` | `os.Chmod` | `if err := os.Chmod(configPath, 0o600); err != nil {` |
| `server/execpriv_unix.go:340` | `os.Stat` | `fi, err := os.Stat(path)` |
| `server/execpriv_unix.go:348` | `os.Chown` | `if err := os.Chown(path, 0, -1); err != nil {` |
| `server/execpriv_unix.go:363` | `os.OpenFile` | `f, err := os.OpenFile(dir, os.O_RDONLY\|syscall.O_DIRECTORY\|syscall.O_NOFOLLOW, 0)` |
| `server/execpriv_unix.go:398` | `os.ReadDir` | `entries, err := os.ReadDir(dir)` |
| `server/execpriv_unix.go:406` | `os.OpenFile` | `f, err := os.OpenFile(filepath.Join(dir, e.Name()), os.O_RDONLY\|syscall.O_NOFOLLOW, 0)` |
| `server/execpriv_unix.go:451` | `os.Mkdir` | `if err := os.Mkdir(dir, mode.Perm()); err != nil && !errors.Is(err, fs.ErrExist) {` |
| `server/execpriv_unix.go:466` | `os.MkdirAll` | `if err := os.MkdirAll(dataDir, 0o755); err != nil {` |
| `server/execpriv_unix.go:471` | `os.Mkdir` | `if err := os.Mkdir(root, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {` |
| `server/execpriv_unix.go:477` | `os.ReadDir` | `entries, err := os.ReadDir(root)` |
| `server/execpriv_unix.go:510` | `os.ReadDir` | `entries, err := os.ReadDir(taskDir)` |
| `server/execpriv_unix.go:553` | `os.OpenFile` | `f, err := os.OpenFile(root, os.O_RDONLY\|unix.O_NONBLOCK\|unix.O_NOFOLLOW, 0)` |
| `server/execpriv_unix.go:557` | `os.Lchown` | `return os.Lchown(root, -1, gid)` |
| `server/execpriv_unix.go:644` | `os.Chmod` | `if err := os.Chmod(dir, 0o755); err != nil {` |
| `server/finding_traffic_export.go:93` | `os.OpenFile` | `f, err := os.OpenFile(path, os.O_CREATE\|os.O_EXCL\|os.O_WRONLY, 0o600)` |
| `server/isolation_unix.go:159` | `os.Stat` | `fi, err := os.Stat(parent)` |
| `server/isolation_unix.go:202` | `os.Stat` | `if _, err := os.Stat(root); err != nil {` |
| `server/isolation_unix.go:210` | `os.Stat` | `fi, err := os.Stat(path)` |
| `server/isolation_unix.go:237` | `os.Stat` | `if _, err := os.Stat(path); err != nil {` |
| `server/isolation_unix.go:242` | `os.Open` | `f, err := os.Open(path)` |
| `server/isolation_unix.go:321` | `os.Open` | `if f, err := os.Open(path); err == nil {` |
| `server/isolation_unix.go:327` | `os.Stat` | `if _, err := os.Stat("/proc/self"); err == nil {` |
| `server/isolation_unix.go:330` | `os.Open` | `if f, err := os.Open(path); err == nil {` |
| `server/isolation_unix.go:338` | `os.CreateTemp` | `if f, err := os.CreateTemp(dir, ".artex-isolation-probe-*"); err == nil {` |
| `server/isolation_unix.go:341` | `os.Remove` | `os.Remove(name)` |
| `server/manager.go:426` | `os.MkdirAll` | `if err := os.MkdirAll(dir, 0o755); err != nil {` |
| `server/manager.go:1852` | `os.Lstat` | `if _, err := os.Lstat(dir); err == nil {` |
| `server/manager.go:1860` | `os.ReadDir` | `entries, err := os.ReadDir(transcriptDir)` |
| `server/manager.go:1881` | `os.MkdirAll` | `if err := os.MkdirAll(parent, 0o700); err != nil {` |
| `server/manager.go:1890` | `os.Rename` | `if err := os.Rename(source, staged); err != nil {` |
| `server/manager.go:1907` | `os.RemoveAll` | `err := os.RemoveAll(s.stageDir)` |
| `server/manager.go:1919` | `os.Lstat` | `if _, err := os.Lstat(move.source); err == nil {` |
| `server/manager.go:1926` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Dir(move.source), 0o755); err != nil {` |
| `server/manager.go:1930` | `os.Rename` | `if err := os.Rename(move.staged, move.source); err != nil {` |
| `server/manager.go:1935` | `os.RemoveAll` | `if err := os.RemoveAll(s.stageDir); err != nil {` |
| `server/pathconfine.go:129` | `os.Lstat` | `fi, err := os.Lstat(candidate)` |
| `server/pathconfine.go:211` | `os.Stat` | `fi, statErr := os.Stat(dirCP.realPath)` |
| `server/pathconfine.go:230` | `os.ReadDir` | `entries, err := os.ReadDir(realRoot)` |
| `server/pathconfine.go:259` | `os.Stat` | `if fi, serr := os.Stat(cp.realPath); serr != nil \|\| fi.IsDir() {` |
| `server/pathconfine.go:276` | `os.Stat` | `if fi, serr := os.Stat(cp.realPath); serr != nil \|\| fi.IsDir() {` |
| `server/pathconfine.go:302` | `os.RemoveAll` | `defer os.RemoveAll(tmp)` |
| `server/pathconfine.go:305` | `os.ReadFile` | `data, rerr := os.ReadFile(item.sourcePath)` |
| `server/pathconfine.go:311` | `os.MkdirAll` | `if err := os.MkdirAll(sub, 0o755); err != nil {` |
| `server/pathconfine.go:314` | `os.WriteFile` | `_ = os.WriteFile(filepath.Join(sub, "SKILL.md"), data, 0o600)` |
| `server/pathconfine.go:316` | `os.WriteFile` | `_ = os.WriteFile(filepath.Join(tmp, item.entryName), data, 0o600)` |
| `server/platform_tools.go:109` | `os.MkdirAll` | `if err := os.MkdirAll(path, 0o755); err != nil {` |
| `server/platform_tools.go:122` | `os.WriteFile` | `if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte(b.String()), 0o644); err != nil {` |
| `server/platform_tools.go:123` | `os.RemoveAll` | `_ = os.RemoveAll(path)` |
| `server/platform_tools.go:162` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Dir(cp.realPath), 0o755); err != nil {` |
| `server/platform_tools.go:165` | `os.WriteFile` | `if err := os.WriteFile(cp.realPath, []byte(a.Content), 0o644); err != nil {` |
| `server/server.go:2526` | `os.RemoveAll` | `defer os.RemoveAll(stage)` |
| `server/server.go:2548` | `os.Open` | `file, err := os.Open(path)` |
| `server/server_mgmt.go:1164` | `os.MkdirAll` | `_ = os.MkdirAll(s.skillDir, 0o755)` |
| `server/server_mgmt.go:1174` | `os.ReadDir` | `entries, err := os.ReadDir(s.skillDir)` |
| `server/server_mgmt.go:1294` | `os.MkdirAll` | `if err := os.MkdirAll(skillPath, 0o755); err != nil {` |
| `server/server_mgmt.go:1329` | `os.WriteFile` | `if err := os.WriteFile(filepath.Join(skillPath, "SKILL.md"), []byte(sb.String()), 0o644); err != nil {` |
| `server/server_mgmt.go:1330` | `os.RemoveAll` | `_ = os.RemoveAll(skillPath)` |
| `server/server_mgmt.go:1338` | `os.RemoveAll` | `_ = os.RemoveAll(skillPath)` |
| `server/server_mgmt.go:1375` | `os.ReadFile` | `raw, err := os.ReadFile(cp.realPath)` |
| `server/server_mgmt.go:1389` | `os.WriteFile` | `if err := os.WriteFile(cp.realPath, updated, 0o644); err != nil {` |
| `server/server_mgmt.go:1641` | `os.MkdirAll` | `_ = os.MkdirAll(s.skillDir, 0o755)` |
| `server/server_mgmt.go:1647` | `os.RemoveAll` | `defer os.RemoveAll(tmp) // no-op after a successful rename` |
| `server/server_mgmt.go:1675` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {` |
| `server/server_mgmt.go:1684` | `os.Create` | `out, err := os.Create(dst)` |
| `server/server_mgmt.go:1703` | `os.Stat` | `if _, err := os.Stat(filepath.Join(tmp, "SKILL.md")); err != nil {` |
| `server/server_mgmt.go:1709` | `os.RemoveAll` | `_ = os.RemoveAll(skillPath)` |
| `server/server_mgmt.go:1711` | `os.Rename` | `if err := os.Rename(tmp, skillPath); err != nil {` |
| `server/server_mgmt.go:1749` | `os.RemoveAll` | `if err := os.RemoveAll(dirCP.entryPath); err != nil {` |
| `server/server_mgmt.go:1863` | `os.Stat` | `fi, err := os.Stat(dirCP.realPath)` |
| `server/server_mgmt.go:1899` | `os.ReadFile` | `data, err := os.ReadFile(cp.realPath)` |
| `server/server_mgmt.go:1943` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Dir(cp.realPath), 0o755); err != nil {` |
| `server/server_mgmt.go:1947` | `os.WriteFile` | `if err := os.WriteFile(cp.realPath, []byte(body.Content), 0o644); err != nil {` |
| `server/server_mgmt.go:1985` | `os.MkdirAll` | `if err := os.MkdirAll(cp.realPath, 0o755); err != nil {` |
| `server/server_mgmt.go:2016` | `os.RemoveAll` | `if err := os.RemoveAll(cp.entryPath); err != nil {` |
| `server/sync_dir_unix.go:13` | `os.Open` | `d, err := os.Open(path)` |
| `server/task_archives.go:195` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Dir(streamPath), archiveDirMode); err != nil {` |
| `server/task_archives.go:198` | `os.OpenFile` | `streamFile, err := os.OpenFile(streamPath, os.O_CREATE\|os.O_EXCL\|os.O_WRONLY, archiveFileMode)` |
| `server/task_archives.go:239` | `os.Remove` | `_ = os.Remove(archivePath)` |
| `server/task_archives.go:280` | `os.Remove` | `_ = os.Remove(remoteJournal)` |
| `server/task_archives.go:323` | `os.MkdirAll` | `if err := os.MkdirAll(restoreParent, archiveDirMode); err != nil {` |
| `server/task_archives.go:330` | `os.RemoveAll` | `defer func() { _ = os.RemoveAll(extracted) }()` |
| `server/task_archives.go:342` | `os.ReadFile` | `manifestRaw, err := os.ReadFile(filepath.Join(extracted, "manifest.json"))` |
| `server/task_archives.go:372` | `os.Open` | `llmRecordsFile, err = os.Open(filepath.Join(extracted, filepath.FromSlash(relative)))` |
| `server/task_archives.go:480` | `os.Rename` | `_ = os.Rename(staged, job.ArchivePath)` |
| `server/task_archives.go:485` | `os.Remove` | `if err := os.Remove(staged); err != nil && !os.IsNotExist(err) {` |
| `server/task_archive_package.go:70` | `os.OpenFile` | `file, err := os.OpenFile(path, os.O_CREATE\|os.O_TRUNC\|os.O_WRONLY, archiveFileMode)` |
| `server/task_archive_package.go:97` | `os.ReadFile` | `if raw, err := os.ReadFile(journalPath); err == nil {` |
| `server/task_archive_package.go:105` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Join(stage.payload, "files"), archiveDirMode); err != nil {` |
| `server/task_archive_package.go:116` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Join(stage.payload, "files"), archiveDirMode); err != nil {` |
| `server/task_archive_package.go:122` | `os.Lstat` | `if _, err := os.Lstat(taskDir); err == nil {` |
| `server/task_archive_package.go:129` | `os.Lstat` | `if _, err := os.Lstat(spillDir); err == nil {` |
| `server/task_archive_package.go:135` | `os.ReadDir` | `entries, err := os.ReadDir(transcriptDir)` |
| `server/task_archive_package.go:169` | `os.Lstat` | `if _, err := os.Lstat(destination); err == nil {` |
| `server/task_archive_package.go:174` | `os.Lstat` | `if _, err := os.Lstat(move.Source); err != nil {` |
| `server/task_archive_package.go:182` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Dir(destination), archiveDirMode); err != nil {` |
| `server/task_archive_package.go:185` | `os.Rename` | `if err := os.Rename(move.Source, destination); err != nil {` |
| `server/task_archive_package.go:198` | `os.RemoveAll` | `err = os.RemoveAll(s.root)` |
| `server/task_archive_package.go:210` | `os.Lstat` | `if _, err := os.Lstat(staged); os.IsNotExist(err) {` |
| `server/task_archive_package.go:216` | `os.Lstat` | `if _, err := os.Lstat(move.Source); err == nil {` |
| `server/task_archive_package.go:223` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Dir(move.Source), 0o755); err != nil {` |
| `server/task_archive_package.go:227` | `os.Rename` | `if err := os.Rename(staged, move.Source); err != nil {` |
| `server/task_archive_package.go:239` | `os.RemoveAll` | `return os.RemoveAll(s.root)` |
| `server/task_archive_package.go:256` | `os.Lstat` | `if _, err := os.Lstat(workspace); err == nil {` |
| `server/task_archive_package.go:265` | `os.Lstat` | `if _, err := os.Lstat(spill); err == nil {` |
| `server/task_archive_package.go:272` | `os.ReadDir` | `entries, err := os.ReadDir(transcripts)` |
| `server/task_archive_package.go:282` | `os.Lstat` | `if _, err := os.Lstat(move.Destination); err == nil {` |
| `server/task_archive_package.go:294` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Dir(move.Destination), 0o755); err != nil {` |
| `server/task_archive_package.go:298` | `os.Rename` | `if err := os.Rename(move.Source, move.Destination); err != nil {` |
| `server/task_archive_package.go:325` | `os.Lstat` | `if _, err := os.Lstat(move.Destination); os.IsNotExist(err) {` |
| `server/task_archive_package.go:331` | `os.Lstat` | `if _, err := os.Lstat(move.Source); err == nil {` |
| `server/task_archive_package.go:338` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Dir(move.Source), archiveDirMode); err != nil {` |
| `server/task_archive_package.go:342` | `os.Rename` | `if err := os.Rename(move.Destination, move.Source); err != nil {` |
| `server/task_archive_package.go:355` | `os.RemoveAll` | `return os.RemoveAll(s.extracted)` |
| `server/task_archive_package.go:364` | `os.ReadDir` | `entries, err := os.ReadDir(parent)` |
| `server/task_archive_package.go:377` | `os.ReadFile` | `raw, err := os.ReadFile(filepath.Join(root, "restore-journal.json"))` |
| `server/task_archive_package.go:380` | `os.RemoveAll` | `if err := os.RemoveAll(root); err != nil {` |
| `server/task_archive_package.go:409` | `os.RemoveAll` | `if err := os.RemoveAll(root); err != nil {` |
| `server/task_archive_package.go:419` | `os.RemoveAll` | `if err := os.RemoveAll(root); err != nil {` |
| `server/task_archive_package.go:431` | `os.ReadDir` | `entries, err := os.ReadDir(parent)` |
| `server/task_archive_package.go:444` | `os.ReadFile` | `raw, err := os.ReadFile(filepath.Join(root, "journal.json"))` |
| `server/task_archive_package.go:452` | `os.RemoveAll` | `if err := os.RemoveAll(root); err != nil {` |
| `server/task_archive_package.go:472` | `os.RemoveAll` | `if err := os.RemoveAll(root); err != nil {` |
| `server/task_archive_package.go:496` | `os.RemoveAll` | `if err := os.RemoveAll(root); err != nil {` |
| `server/task_archive_package.go:505` | `os.ReadDir` | `entries, err := os.ReadDir(root)` |
| `server/task_archive_package.go:534` | `os.Remove` | `if err := os.Remove(staged); err != nil && !os.IsNotExist(err) {` |
| `server/task_archive_package.go:543` | `os.Lstat` | `if _, err := os.Lstat(original); err == nil {` |
| `server/task_archive_package.go:550` | `os.Rename` | `if err := os.Rename(staged, original); err != nil {` |
| `server/task_archive_package.go:559` | `os.Lstat` | `if _, err := os.Lstat(staged); err == nil {` |
| `server/task_archive_package.go:560` | `os.Lstat` | `if _, originalErr := os.Lstat(archivePath); originalErr == nil {` |
| `server/task_archive_package.go:569` | `os.Rename` | `if err := os.Rename(archivePath, staged); err == nil {` |
| `server/task_archive_package.go:581` | `os.MkdirAll` | `if err = os.MkdirAll(filepath.Dir(path), archiveDirMode); err != nil {` |
| `server/task_archive_package.go:584` | `os.OpenFile` | `manifestFile, err := os.OpenFile(` |
| `server/task_archive_package.go:601` | `os.Remove` | `_ = os.Remove(temporary)` |
| `server/task_archive_package.go:602` | `os.OpenFile` | `file, err := os.OpenFile(temporary, os.O_CREATE\|os.O_EXCL\|os.O_WRONLY, archiveFileMode)` |
| `server/task_archive_package.go:610` | `os.Remove` | `_ = os.Remove(temporary)` |
| `server/task_archive_package.go:660` | `os.Open` | `input, err := os.Open(current)` |
| `server/task_archive_package.go:686` | `os.Stat` | `stat, err := os.Stat(temporary)` |
| `server/task_archive_package.go:692` | `os.Rename` | `if err := os.Rename(temporary, path); err != nil {` |
| `server/task_archive_package.go:695` | `os.Chmod` | `if err := os.Chmod(path, archiveFileMode); err != nil {` |
| `server/task_archive_package.go:703` | `os.Open` | `file, err := os.Open(path)` |
| `server/task_archive_package.go:726` | `os.MkdirAll` | `if err := os.MkdirAll(destination, archiveDirMode); err != nil {` |
| `server/task_archive_package.go:754` | `os.MkdirAll` | `if err := os.MkdirAll(target, archiveDirMode); err != nil {` |
| `server/task_archive_package.go:758` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Dir(target), archiveDirMode); err != nil {` |
| `server/task_archive_package.go:761` | `os.OpenFile` | `output, err := os.OpenFile(target, os.O_CREATE\|os.O_EXCL\|os.O_WRONLY, fs.FileMode(header.Mode)&0o777)` |
| `server/task_archive_remote.go:33` | `os.Remove` | `if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {` |
| `server/task_archive_remote.go:51` | `os.MkdirAll` | `if err := os.MkdirAll(dir, archiveDirMode); err != nil {` |
| `server/task_archive_remote.go:54` | `os.CreateTemp` | `f, err := os.CreateTemp(dir, ".journal-")` |
| `server/task_archive_remote.go:59` | `os.Remove` | `defer os.Remove(tmp)` |
| `server/task_archive_remote.go:66` | `os.Rename` | `if err := os.Rename(tmp, name); err != nil {` |
| `server/task_archive_remote.go:79` | `os.ReadDir` | `entries, err := os.ReadDir(dir)` |
| `server/task_archive_remote.go:100` | `os.ReadFile` | `raw, err := os.ReadFile(name)` |
| `server/task_archive_remote.go:145` | `os.Remove` | `return os.Remove(name)` |
| `server/upload_open_unix.go:13` | `os.OpenFile` | `return os.OpenFile(dest, os.O_WRONLY\|os.O_CREATE\|os.O_TRUNC\|syscall.O_NOFOLLOW, 0o644)` |
| `server/upload_open_windows.go:8` | `os.OpenFile` | `return os.OpenFile(dest, os.O_WRONLY\|os.O_CREATE\|os.O_TRUNC, 0o644)` |
| `server/workspace.go:124` | `os.Stat` | `fi, err := os.Stat(abs)` |
| `server/workspace.go:133` | `os.ReadDir` | `ents, err := os.ReadDir(abs)` |
| `server/workspace.go:171` | `os.Stat` | `fi, err := os.Stat(abs)` |
| `server/workspace.go:184` | `os.ReadFile` | `data, err := os.ReadFile(abs)` |
| `server/workspace.go:212` | `os.Stat` | `if fi, err := os.Stat(abs); err == nil && fi.IsDir() {` |
| `server/workspace.go:216` | `os.MkdirAll` | `if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {` |
| `server/workspace.go:220` | `os.WriteFile` | `if err := os.WriteFile(abs, []byte(req.Content), 0o644); err != nil {` |
| `server/workspace.go:242` | `os.MkdirAll` | `if err := os.MkdirAll(abs, 0o755); err != nil {` |
| `server/workspace.go:271` | `os.RemoveAll` | `if err := os.RemoveAll(cp.entryPath); err != nil {` |
| `server/workspace.go:286` | `os.Stat` | `fi, err := os.Stat(abs)` |
| `server/workspace.go:304` | `os.Stat` | `if fi, err := os.Stat(dir.realPath); err != nil \|\| !fi.IsDir() {` |
| `server/workspace.go:366` | `os.Lstat` | `fi, err := os.Lstat(dest)` |
