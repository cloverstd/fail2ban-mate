package mate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	Server         string `json:"server"`
	Token          string `json:"token"`
	NodeID         string `json:"node_id"`
	StatePath      string `json:"state_path"`
	GeoPath        string `json:"geo_path"`
	Fail2banClient string `json:"fail2ban_client"`
}
type State struct {
	Sequence              int64                     `json:"sequence"`
	Known                 map[string]map[string]Ban `json:"known"`
	Unavailable           []string                  `json:"unavailable"`
	Events                []Event                   `json:"events"`
	Results               map[string]Result         `json:"results"`
	Completed             map[string]Result         `json:"completed"`
	CompletedAt           map[string]int64          `json:"completed_at"`
	Policies              []Policy                  `json:"policies"`
	PolicyRevision        int64                     `json:"policy_revision"`
	AppliedPolicyRevision int64                     `json:"applied_policy_revision"`
	Owned                 map[string]bool           `json:"owned"`
	Remote                RemoteConfig              `json:"remote"`
}

func NewState() *State {
	return &State{Known: map[string]map[string]Ban{}, Events: []Event{}, Results: map[string]Result{}, Completed: map[string]Result{}, CompletedAt: map[string]int64{}, Policies: []Policy{}, Owned: map[string]bool{}, Remote: RemoteConfig{Mode: "websocket", PollInterval: 30}}
}
func LoadState(path string) (*State, error) {
	s := NewState()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("invalid state file; refusing to discard pending commands: %w", err)
	}
	return s, nil
}
func WriteJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return AtomicWrite(path, b, 0600)
}
func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".mate-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func UUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(b[:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:]))
}
