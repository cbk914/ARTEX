package traffic

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const (
	defaultArchiveBlobLimit     = int64(4 << 30)
	hardArchiveBlobLimit        = int64(32 << 30)
	defaultTrafficSnapshotLimit = int64(256 << 20)
	hardTrafficSnapshotLimit    = int64(4 << 30)
)

var errTrafficArchiveBudget = errors.New("traffic archive exceeds its manifest limit")

type trafficArchiveWriter struct {
	out          io.Writer
	written, max int64
}

func (w *trafficArchiveWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.max-w.written {
		return 0, errTrafficArchiveBudget
	}
	n, err := w.out.Write(p)
	w.written += int64(n)
	return n, err
}

type archiveReadContext struct {
	ctx context.Context
	r   io.Reader
}

func (r archiveReadContext) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

const (
	archiveVersionV1 = 1
	archiveVersionV2 = 2
)

// ArchiveSnapshot is the portable traffic subset embedded in one task archive.
// Large content-addressed bodies are copied alongside this manifest rather than
// base64-encoded, preserving deduplication and allowing the tar writer to stream.
type ArchiveSnapshot struct {
	Version   int               `json:"version"`
	Exchanges []ArchiveExchange `json:"exchanges"`
	Blobs     []string          `json:"blobs"`
}

type ArchiveExchange struct {
	ID             string  `json:"id"`
	TS             int64   `json:"ts"`
	Host           string  `json:"host"`
	Method         string  `json:"method"`
	URLTemplate    string  `json:"url_template"`
	URL            string  `json:"url"`
	Status         int     `json:"status"`
	ContentType    string  `json:"content_type"`
	ReqLen         int     `json:"req_len"`
	RespLen        int     `json:"resp_len"`
	ReqHead        string  `json:"req_head"`
	ReqBody        []byte  `json:"req_body,omitempty"`
	ReqBlob        string  `json:"req_blob,omitempty"`
	RespHead       string  `json:"resp_head"`
	RespBody       []byte  `json:"resp_body,omitempty"`
	RespBlob       string  `json:"resp_blob,omitempty"`
	Rewritten      bool    `json:"rewritten,omitempty"`
	RewriteRuleIDs []int64 `json:"rewrite_rule_ids,omitempty"`
}

// ExportHosts writes an exact-host snapshot to dir. It holds the traffic writer
// lock while reading SQLite and blobs, so each body and its index row come from
// one consistent point in time.
func (t *Traffic) ExportHosts(hosts []string, dir string) (int64, error) {
	return t.ExportHostsContext(context.Background(), hosts, dir, defaultArchiveBlobLimit)
}

// ExportHostsContext bounds each blob before the archive package is built.
// A changed or symlinked blob fails export rather than copying unintended data.
func (t *Traffic) ExportHostsContext(ctx context.Context, hosts []string, dir string, maxBlobBytes int64) (int64, error) {
	return t.ExportHostsBudget(ctx, hosts, dir, maxBlobBytes, defaultTrafficSnapshotLimit)
}

// ExportHostsBudget streams the version-2 traffic manifest to a private
// temporary file. The final name is published only after all rows and blobs
// have passed their bounds and integrity checks.
func (t *Traffic) ExportHostsBudget(ctx context.Context, hosts []string, dir string, maxBlobBytes, maxSnapshotBytes int64) (int64, error) {
	if t == nil || len(hosts) == 0 {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if maxBlobBytes <= 0 || maxBlobBytes > hardArchiveBlobLimit {
		return 0, errors.New("invalid traffic archive blob limit")
	}
	if maxSnapshotBytes <= 0 || maxSnapshotBytes > hardTrafficSnapshotLimit {
		return 0, errors.New("invalid traffic archive manifest limit")
	}
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o700); err != nil {
		return 0, err
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	temporary, err := os.CreateTemp(dir, ".traffic-*.json")
	if err != nil {
		return 0, err
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	manifest := &trafficArchiveWriter{out: temporary, max: maxSnapshotBytes}
	if _, err := manifest.Write([]byte(fmt.Sprintf(`{"version":%d,"exchanges":[`, archiveVersionV2))); err != nil {
		return 0, err
	}
	unique := uniqueArchiveHosts(hosts)
	placeholders := make([]string, len(unique))
	args := make([]any, len(unique))
	for i, host := range unique {
		placeholders[i] = "?"
		args[i] = host
	}
	rows, err := t.db.QueryContext(ctx, `SELECT id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path
FROM exchanges WHERE host IN (`+strings.Join(placeholders, ",")+`) ORDER BY ts,id`, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	blobs := map[string]struct{}{}
	var count int64
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		var item ArchiveExchange
		var legacyPath string
		if err := rows.Scan(&item.ID, &item.TS, &item.Host, &item.Method, &item.URLTemplate,
			&item.URL, &item.Status, &item.ContentType, &item.ReqLen, &item.RespLen, &legacyPath); err != nil {
			return 0, err
		}
		var reqBlob, respBlob sql.NullString
		var bodyBytes int64
		bodyErr := t.db.QueryRowContext(ctx, `SELECT COALESCE(length(CAST(req_head AS BLOB)),0)+COALESCE(length(req_body),0)+COALESCE(length(CAST(resp_head AS BLOB)),0)+COALESCE(length(resp_body),0)
FROM exchange_bodies WHERE id=?`, item.ID).Scan(&bodyBytes)
		if bodyErr != nil && !errors.Is(bodyErr, sql.ErrNoRows) {
			return 0, bodyErr
		}
		if bodyBytes < 0 || bodyBytes > maxSnapshotBytes-manifest.written {
			return 0, errTrafficArchiveBudget
		}
		err := t.db.QueryRowContext(ctx, `SELECT req_head,req_body,req_blob,resp_head,resp_body,resp_blob
FROM exchange_bodies WHERE id=?`, item.ID).Scan(&item.ReqHead, &item.ReqBody, &reqBlob, &item.RespHead, &item.RespBody, &respBlob)
		if errors.Is(err, sql.ErrNoRows) && strings.TrimSpace(legacyPath) != "" {
			req, readErr := t.readLegacyExchangeFile(legacyPath, "request.http")
			if readErr != nil {
				return 0, readErr
			}
			resp, readErr := t.readLegacyExchangeFile(legacyPath, "response.http")
			if readErr != nil {
				return 0, readErr
			}
			item.ReqHead, item.RespHead = string(req), string(resp)
		} else if err != nil {
			return 0, err
		}
		actualBodyBytes := int64(len(item.ReqHead)) + int64(len(item.ReqBody)) + int64(len(item.RespHead)) + int64(len(item.RespBody))
		if actualBodyBytes < 0 || actualBodyBytes > maxSnapshotBytes-manifest.written {
			return 0, errTrafficArchiveBudget
		}
		item.ReqBlob, item.RespBlob = reqBlob.String, respBlob.String
		rewritten, ruleIDs, err := t.RewriteInfo(item.ID)
		if err != nil {
			return 0, err
		}
		if rewritten {
			item.Rewritten = true
			item.RewriteRuleIDs = ruleIDs
		}
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash != "" {
				blobs[hash] = struct{}{}
			}
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return 0, err
		}
		if count > 0 {
			if _, err := manifest.Write([]byte(",")); err != nil {
				return 0, err
			}
		}
		if _, err := manifest.Write(encoded); err != nil {
			return 0, err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	_ = rows.Close()
	if _, err := manifest.Write([]byte(`],"blobs":`)); err != nil {
		return 0, err
	}
	if len(blobs) > 0 {
		hashes := make([]string, 0, len(blobs))
		for hash := range blobs {
			hashes = append(hashes, hash)
		}
		sort.Strings(hashes)
		if _, err := manifest.Write([]byte("[")); err != nil {
			return 0, err
		}
		for i, hash := range hashes {
			if i > 0 {
				if _, err := manifest.Write([]byte(",")); err != nil {
					return 0, err
				}
			}
			encoded, err := json.Marshal(hash)
			if err != nil {
				return 0, err
			}
			if _, err := manifest.Write(encoded); err != nil {
				return 0, err
			}
			if err := t.copyArchiveBlob(ctx, hash, filepath.Join(dir, "blobs"), maxBlobBytes); err != nil {
				return 0, err
			}
		}
		if _, err := manifest.Write([]byte("]")); err != nil {
			return 0, err
		}
	} else if _, err := manifest.Write([]byte("null")); err != nil {
		return 0, err
	}
	if _, err := manifest.Write([]byte("}")); err != nil {
		return 0, err
	}
	if err := errors.Join(temporary.Sync(), ctx.Err()); err != nil {
		return 0, err
	}
	if err := temporary.Close(); err != nil {
		return 0, err
	}
	destination := filepath.Join(dir, "traffic.json")
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	if err := os.Rename(temporary.Name(), destination); err != nil {
		return 0, err
	}
	return count, nil
}

func (t *Traffic) copyArchiveBlob(ctx context.Context, hash, destinationDir string, maxBytes int64) error {
	if !blobHashRe.MatchString(hash) {
		return errors.New("invalid traffic archive blob hash")
	}
	root, err := os.OpenRoot(t.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	var source *os.File
	var selected os.FileInfo
	for _, relative := range []string{
		filepath.Join("_blobs", "sha256", hash[:2], hash+".bin"),
		filepath.Join("_blobs", "sha256", hash[:2], hash[2:4], hash+".bin"),
	} {
		selected, err = root.Lstat(relative)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if !selected.Mode().IsRegular() || selected.Size() < 0 || selected.Size() > maxBytes {
			return errors.New("traffic archive blob is unsafe or exceeds its limit")
		}
		source, err = root.Open(relative)
		if err != nil {
			return err
		}
		opened, statErr := source.Stat()
		if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(selected, opened) || opened.Size() != selected.Size() {
			source.Close()
			return errors.New("traffic archive blob changed at open")
		}
		break
	}
	if source == nil {
		return errors.New("traffic archive blob is missing")
	}
	defer source.Close()
	temporary, err := os.CreateTemp(destinationDir, ".blob-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	hasher := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(temporary, hasher), archiveReadContext{ctx: ctx, r: io.LimitReader(source, maxBytes+1)})
	final, statErr := source.Stat()
	if copyErr == nil {
		copyErr = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err := errors.Join(copyErr, statErr, closeErr, ctx.Err()); err != nil {
		return err
	}
	if n > maxBytes || n != selected.Size() || !os.SameFile(selected, final) || final.Size() != selected.Size() || !final.ModTime().Equal(selected.ModTime()) || hex.EncodeToString(hasher.Sum(nil)) != hash {
		return errors.New("traffic archive blob changed or failed integrity check")
	}
	destination := filepath.Join(destinationDir, hash+".bin")
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(temporary.Name(), destination)
}

func (t *Traffic) copyImportedArchiveBlob(ctx context.Context, root *os.Root, hash string, maxBytes int64) error {
	relative := filepath.Join("blobs", hash+".bin")
	selected, err := root.Lstat(relative)
	if err != nil {
		return err
	}
	if !selected.Mode().IsRegular() || selected.Size() < 0 || selected.Size() > maxBytes {
		return errors.New("archived traffic blob is unsafe or exceeds its limit")
	}
	source, err := root.Open(relative)
	if err != nil {
		return err
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(selected, opened) || opened.Size() != selected.Size() {
		return errors.New("archived traffic blob changed at open")
	}
	bucket := filepath.Join(t.dir, "_blobs", "sha256", hash[:2])
	if err := os.MkdirAll(bucket, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(bucket, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(bucket, ".restore-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	hasher := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(temporary, hasher), archiveReadContext{ctx: ctx, r: io.LimitReader(source, maxBytes+1)})
	final, statErr := source.Stat()
	if copyErr == nil {
		copyErr = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err := errors.Join(copyErr, statErr, closeErr, ctx.Err()); err != nil {
		return err
	}
	if n != selected.Size() || n > maxBytes || !os.SameFile(selected, final) || final.Size() != selected.Size() || !final.ModTime().Equal(selected.ModTime()) || hex.EncodeToString(hasher.Sum(nil)) != hash {
		return fmt.Errorf("traffic blob checksum or source identity mismatch: %s", hash)
	}
	destination := filepath.Join(bucket, hash+".bin")
	if existing, err := os.Lstat(destination); err == nil {
		if !existing.Mode().IsRegular() || existing.Size() != n {
			return errors.New("existing traffic blob is unsafe")
		}
		file, err := os.Open(destination)
		if err != nil {
			return err
		}
		openedExisting, statErr := file.Stat()
		if statErr != nil || !openedExisting.Mode().IsRegular() || !os.SameFile(existing, openedExisting) {
			file.Close()
			return errors.New("existing traffic blob changed at open")
		}
		existingHash := sha256.New()
		_, readErr := io.Copy(existingHash, archiveReadContext{ctx: ctx, r: io.LimitReader(file, maxBytes+1)})
		closeErr := file.Close()
		if err := errors.Join(readErr, closeErr, ctx.Err()); err != nil {
			return err
		}
		if hex.EncodeToString(existingHash.Sum(nil)) != hash {
			return errors.New("existing traffic blob failed integrity check")
		}
		return os.Chmod(destination, 0o600)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(temporary.Name(), destination)
}

// ImportArchive imports only missing exchange IDs. Current hot rows always win,
// and repeated restore attempts are safe after a partial external failure.
// Version 1 archives carry no rewrite provenance (imported as unrewritten).
// Version 2 archives carry per-exchange rewritten + rewrite_rule_ids and
// reconstruct minimal applied rows in exchange_rewrites (phase='archived',
// outcome='applied', rule_snapshot=NULL) so RewriteInfo and the rewritten list
// filter return the same provenance without inventing a rule snapshot.
func (t *Traffic) ImportArchive(dir string) (int64, error) {
	return t.ImportArchiveContext(context.Background(), dir)
}

// ImportArchiveContext binds the SQLite restore transaction and per-item
// processing to the archive job context. Package size validation remains with
// the caller, before this function opens the extracted manifest.
func (t *Traffic) ImportArchiveContext(ctx context.Context, dir string) (int64, error) {
	return t.ImportArchiveBudget(ctx, dir, defaultTrafficSnapshotLimit, defaultArchiveBlobLimit)
}

// ImportArchiveBudget checks extracted traffic files before loading the
// manifest or copying blobs. Larger historical manifests require an explicit
// reviewed budget override at the archive worker.
func (t *Traffic) ImportArchiveBudget(ctx context.Context, dir string, maxSnapshotBytes, maxBlobBytes int64) (int64, error) {
	if t == nil {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if maxSnapshotBytes <= 0 || maxSnapshotBytes > hardTrafficSnapshotLimit || maxBlobBytes <= 0 || maxBlobBytes > hardArchiveBlobLimit {
		return 0, errors.New("invalid traffic archive restore budget")
	}
	root, err := os.OpenRoot(dir)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer root.Close()
	info, err := root.Lstat("traffic.json")
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxSnapshotBytes {
		return 0, errTrafficArchiveBudget
	}
	file, err := root.Open("traffic.json")
	if err != nil {
		return 0, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || opened.Size() != info.Size() {
		file.Close()
		return 0, errors.New("traffic archive manifest changed at open")
	}
	raw, readErr := io.ReadAll(archiveReadContext{ctx: ctx, r: io.LimitReader(file, maxSnapshotBytes+1)})
	final, finalErr := file.Stat()
	closeErr := file.Close()
	if err := errors.Join(readErr, finalErr, closeErr, ctx.Err()); err != nil {
		return 0, err
	}
	if int64(len(raw)) != info.Size() || int64(len(raw)) > maxSnapshotBytes || !os.SameFile(info, final) || final.Size() != info.Size() || !final.ModTime().Equal(info.ModTime()) {
		return 0, errTrafficArchiveBudget
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var snapshot ArchiveSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return 0, err
	}
	if snapshot.Version != archiveVersionV1 && snapshot.Version != archiveVersionV2 {
		return 0, fmt.Errorf("unsupported traffic archive version %d", snapshot.Version)
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	for _, hash := range snapshot.Blobs {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if !blobHashRe.MatchString(hash) {
			return 0, fmt.Errorf("invalid archived traffic blob %q", hash)
		}
		if err := t.copyImportedArchiveBlob(ctx, root, hash, maxBlobBytes); err != nil {
			return 0, err
		}
	}
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	var imported int64
	for _, item := range snapshot.Exchanges {
		if err := ctx.Err(); err != nil {
			return imported, err
		}
		res, err := tx.Exec(`INSERT OR IGNORE INTO exchanges(id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
VALUES(?,?,?,?,?,?,?,?,?,?,'')`, item.ID, item.TS, item.Host, item.Method, item.URLTemplate,
			item.URL, item.Status, item.ContentType, item.ReqLen, item.RespLen)
		if err != nil {
			return imported, err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO exchange_bodies(id,req_head,req_body,req_blob,resp_head,resp_body,resp_blob)
VALUES(?,?,?,?,?,?,?)`, item.ID, item.ReqHead, item.ReqBody, nullIfEmpty(item.ReqBlob),
			item.RespHead, item.RespBody, nullIfEmpty(item.RespBlob)); err != nil {
			return imported, err
		}
		for _, hash := range []string{item.ReqBlob, item.RespBlob} {
			if hash != "" {
				if _, err := tx.Exec(`INSERT OR IGNORE INTO blob_refs(hash,exchange_id) VALUES(?,?)`, hash, item.ID); err != nil {
					return imported, err
				}
			}
		}
		if snapshot.Version >= archiveVersionV2 && item.Rewritten {
			if err := insertArchivedRewriteProvenance(tx, item.ID, item.RewriteRuleIDs); err != nil {
				return imported, err
			}
		}
		if t.fts {
			var rowID int64
			if err := tx.QueryRow(`SELECT rowid FROM exchanges WHERE id=?`, item.ID).Scan(&rowID); err != nil {
				return imported, err
			}
			content := strings.Join([]string{item.URL, item.ReqHead, string(item.ReqBody), item.RespHead, string(item.RespBody)}, "\n")
			if _, err := tx.Exec(`INSERT INTO ex_fts(rowid,content) VALUES(?,?)`, rowID, content); err != nil {
				return imported, err
			}
		}
		imported++
	}
	if err := ctx.Err(); err != nil {
		return imported, err
	}
	if err := tx.Commit(); err != nil {
		return imported, err
	}
	return imported, nil
}

// insertArchivedRewriteProvenance writes minimal applied rows so RewriteInfo
// and the traffic list's rewritten flag/filter return the exact archived
// provenance without fabricating a rule snapshot or request/response phase.
func insertArchivedRewriteProvenance(tx *sql.Tx, exchangeID string, ruleIDs []int64) error {
	ids := normalizeArchiveRuleIDs(ruleIDs)
	if len(ids) == 0 {
		_, err := tx.Exec(`INSERT INTO exchange_rewrites(exchange_id,seq,phase,rule_id,outcome,reason)
VALUES(?,0,'archived',NULL,'applied','archived')`, exchangeID)
		return err
	}
	for seq, rid := range ids {
		if _, err := tx.Exec(`INSERT INTO exchange_rewrites(exchange_id,seq,phase,rule_id,outcome,reason)
VALUES(?,?,'archived',?,'applied','archived')`, exchangeID, seq, rid); err != nil {
			return err
		}
	}
	return nil
}

func normalizeArchiveRuleIDs(ids []int64) []int64 {
	if len(ids) == 0 {
		return nil
	}
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id > 0 {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func uniqueArchiveHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}
