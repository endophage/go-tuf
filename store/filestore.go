package store

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/endophage/go-tuf/data"
	"github.com/endophage/go-tuf/encrypted"
	"github.com/endophage/go-tuf/errors"
	"github.com/endophage/go-tuf/util"
)

// topLevelManifests determines the order signatures are verified when committing.
var topLevelManifests = []string{
	"root",
	"targets",
	"snapshot",
	"timestamp",
}

type persistedKeys struct {
	Encrypted bool            `json:"encrypted"`
	Data      json.RawMessage `json:"data"`
}

func FileSystemStore(dir string, p util.PassphraseFunc) LocalStore {
	return &fileSystemStore{
		dir:            dir,
		passphraseFunc: p,
		keys:           make(map[string][]*data.Key),
	}
}

type fileSystemStore struct {
	dir            string
	passphraseFunc util.PassphraseFunc

	// keys is a cache of persisted keys to avoid decrypting multiple times
	keys map[string][]*data.Key
}

func (f *fileSystemStore) repoDir() string {
	return filepath.Join(f.dir, "repository")
}

func (f *fileSystemStore) stagedDir() string {
	return filepath.Join(f.dir, "staged")
}

func (f *fileSystemStore) GetMeta(name string) (json.RawMessage, error) {
	jsonName := fmt.Sprintf("%s.json", name)
	var meta json.RawMessage
	var err error
	notExists := func(path string) bool {
		_, err := os.Stat(path)
		return os.IsNotExist(err)
	}
	path := filepath.Join(f.stagedDir(), jsonName)
	if notExists(path) {
		path = filepath.Join(f.repoDir(), jsonName)
		if notExists(path) {
			return nil, errors.ErrFileNotFound{path}
		}
	}
	meta, err = ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return meta, nil
}

func (f *fileSystemStore) SetMeta(name string, meta json.RawMessage) error {
	jsonName := fmt.Sprintf("%s.json", name)
	if err := f.createDirs(); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(f.stagedDir(), jsonName), meta, 0644); err != nil {
		return err
	}
	return nil
}

func (f *fileSystemStore) createDirs() error {
	for _, dir := range []string{"keys", "repository", "staged/targets"} {
		if err := os.MkdirAll(filepath.Join(f.dir, dir), 0755); err != nil {
			return err
		}
	}
	return nil
}

func (f *fileSystemStore) WalkStagedTargets(paths []string, targetsFn targetsWalkFunc) error {
	if len(paths) == 0 {
		walkFunc := func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !info.Mode().IsRegular() {
				return nil
			}
			rel, err := filepath.Rel(filepath.Join(f.stagedDir(), "targets"), path)
			if err != nil {
				return err
			}
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()
			meta, err := util.GenerateFileMeta(file, "sha256")
			if err != nil {
				return err
			}
			return targetsFn(rel, meta)
		}
		return filepath.Walk(filepath.Join(f.stagedDir(), "targets"), walkFunc)
	}

	// check all the files exist before processing any files
	for _, path := range paths {
		realPath := filepath.Join(f.stagedDir(), "targets", path)
		if _, err := os.Stat(realPath); err != nil {
			if os.IsNotExist(err) {
				return errors.ErrFileNotFound{realPath}
			}
			return err
		}
	}

	for _, path := range paths {
		realPath := filepath.Join(f.stagedDir(), "targets", path)
		file, err := os.Open(realPath)
		if err != nil {
			if os.IsNotExist(err) {
				return errors.ErrFileNotFound{realPath}
			}
			return err
		}
		meta, err := util.GenerateFileMeta(file, "sha256")
		if err != nil {
			return err
		}
		err = targetsFn(path, meta)
		file.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *fileSystemStore) createRepoFile(path string) (*os.File, error) {
	dst := filepath.Join(f.repoDir(), path)
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return nil, err
	}
	return os.Create(dst)
}

func (f *fileSystemStore) Commit(meta map[string]json.RawMessage, consistentSnapshot bool, hashes map[string]data.Hashes) error {
	isTarget := func(path string) bool {
		return strings.HasPrefix(path, "targets/")
	}
	shouldCopyHashed := func(path string) bool {
		return consistentSnapshot && path != "timestamp.json"
	}
	shouldCopyUnhashed := func(path string) bool {
		return !consistentSnapshot || !isTarget(path)
	}
	copyToRepo := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(f.stagedDir(), path)
		if err != nil {
			return err
		}
		var paths []string
		if shouldCopyHashed(rel) {
			relHashes := hashes[strings.TrimSuffix(rel, ".json")]
			paths = append(paths, util.HashedPaths(rel, relHashes)...)
		}
		if shouldCopyUnhashed(rel) {
			paths = append(paths, rel)
		}
		var files []io.Writer
		for _, path := range paths {
			file, err := f.createRepoFile(path)
			if err != nil {
				return err
			}
			defer file.Close()
			files = append(files, file)
		}
		staged, err := os.Open(path)
		if err != nil {
			return err
		}
		defer staged.Close()
		if _, err = io.Copy(io.MultiWriter(files...), staged); err != nil {
			return err
		}
		return nil
	}
	needsRemoval := func(path string) bool {
		if consistentSnapshot {
			// strip out the hash
			name := strings.SplitN(filepath.Base(path), ".", 2)
			if name[1] == "" {
				return false
			}
			path = filepath.Join(filepath.Dir(path), name[1])
		}
		_, ok := hashes[path]
		return !ok
	}
	removeFile := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(f.repoDir(), path)
		if err != nil {
			return err
		}
		if !info.IsDir() && isTarget(rel) && needsRemoval(rel) {
			if err := os.Remove(path); err != nil {
				// TODO: log / handle error
			}
			// TODO: remove empty directory
		}
		return nil
	}
	if err := filepath.Walk(f.stagedDir(), copyToRepo); err != nil {
		return err
	}
	if err := filepath.Walk(f.repoDir(), removeFile); err != nil {
		return err
	}
	return f.Clean()
}

func (f *fileSystemStore) GetKeys(role string) ([]*data.Key, error) {
	if keys, ok := f.keys[role]; ok {
		return keys, nil
	}
	keys, _, err := f.loadKeys(role)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return keys, nil
}

func (f *fileSystemStore) SaveKey(role string, key *data.Key) error {
	if err := f.createDirs(); err != nil {
		return err
	}

	// add the key to the existing keys (if any)
	keys, pass, err := f.loadKeys(role)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	keys = append(keys, key)

	// if loadKeys didn't return a passphrase (because no keys yet exist)
	// and passphraseFunc is set, get the passphrase so the keys file can
	// be encrypted later (passphraseFunc being nil indicates the keys file
	// should not be encrypted)
	if pass == nil && f.passphraseFunc != nil {
		pass, err = f.passphraseFunc(role, true)
		if err != nil {
			return err
		}
	}

	pk := &persistedKeys{}
	if pass != nil {
		pk.Data, err = encrypted.Marshal(keys, pass)
		if err != nil {
			return err
		}
		pk.Encrypted = true
	} else {
		pk.Data, err = json.MarshalIndent(keys, "", "\t")
		if err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(pk, "", "\t")
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(f.keysPath(role), append(data, '\n'), 0600); err != nil {
		return err
	}
	f.keys[role] = keys
	return nil
}

// loadKeys loads keys for the given role and returns them along with the
// passphrase (if read) so that callers don't need to re-read it.
func (f *fileSystemStore) loadKeys(role string) ([]*data.Key, []byte, error) {
	file, err := os.Open(f.keysPath(role))
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	pk := &persistedKeys{}
	if err := json.NewDecoder(file).Decode(pk); err != nil {
		return nil, nil, err
	}

	var keys []*data.Key
	if !pk.Encrypted {
		if err := json.Unmarshal(pk.Data, &keys); err != nil {
			return nil, nil, err
		}
		return keys, nil, nil
	}

	// the keys are encrypted so cannot be loaded if passphraseFunc is not set
	if f.passphraseFunc == nil {
		return nil, nil, errors.ErrPassphraseRequired{role}
	}

	pass, err := f.passphraseFunc(role, false)
	if err != nil {
		return nil, nil, err
	}
	if err := encrypted.Unmarshal(pk.Data, &keys, pass); err != nil {
		return nil, nil, err
	}
	return keys, pass, nil
}

func (f *fileSystemStore) keysPath(role string) string {
	jsonRolePath := fmt.Sprintf("%s.json", role)
	return filepath.Join(f.dir, "keys", jsonRolePath)
}

func (f *fileSystemStore) Clean() error {
	if err := os.RemoveAll(f.stagedDir()); err != nil {
		return err
	}
	return os.MkdirAll(filepath.Join(f.stagedDir(), "targets"), 0755)
}
