package main

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/dynacert"
	"github.com/pyke369/golang-support/fqdn"
	"github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/ulog"
)

const (
	progname = "salt-pki"
	version  = "1.0.0"
)

type PEER struct {
	hash  string
	items int64
	seen  time.Time
}
type ITEM struct {
	Hash     string `json:"hash"`
	Modified int64  `json:"modified"`
	Seen     int64  `json:"seen"`
}

var (
	config    *uconfig.UConfig
	log       *ulog.ULog
	lock      sync.RWMutex
	id        = ""
	root      = "/etc/salt/pki/master"
	backup    = "/etc/salt/pki/master/backup"
	filter    = "minions*"
	hash      = ""
	peers     = map[string]*PEER{}
	items     = map[string]*ITEM{}
	transport = &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
)

// build local state
func local() {
	roots, _ := filepath.Glob(filepath.Join(root, filter))
	hasher := sha1.New()
	for _, entry := range roots {
		filepath.Walk(entry, func(path string, info os.FileInfo, err error) error {
			if info.Mode().IsRegular() && !strings.Contains(path, "/.") {
				key := strings.TrimPrefix(path, root+"/")
				if content, err := ioutil.ReadFile(path); err == nil && len(content) > 0 {
					sum := fmt.Sprintf("%x", sha1.Sum(content))
					io.WriteString(hasher, key+sum)
					lock.Lock()
					if items[key] == nil {
						items[key] = &ITEM{}
					}
					item := items[key]
					lock.Unlock()
					item.Hash, item.Modified, item.Seen = sum, info.ModTime().Unix(), time.Now().Unix()
				}
			}
			return nil
		})
	}
	nhash, modified := fmt.Sprintf("%x", hasher.Sum(nil)), false
	if nhash != hash {
		hash = nhash
		modified = true
	}
	lock.Lock()
	for key, item := range items {
		if time.Now().Unix()-item.Seen >= 60 {
			delete(items, key)
			modified = true
		}
	}
	if modified {
		log.Info(map[string]interface{}{"id": id, "event": "local", "items": len(items), "hash": hash})
	}
	lock.Unlock()
}

// poll peers states
func peer(name, remote string) {
	lock.Lock()
	if peers[name] == nil {
		peers[name] = &PEER{}
	}
	peer := peers[name]
	lock.Unlock()
	client := &http.Client{Timeout: 10 * time.Second, Transport: transport}
	if response, err := client.Get(remote + "/_state"); err == nil {
		if response.StatusCode == http.StatusOK {
			if content, err := ioutil.ReadAll(response.Body); err == nil {
				var payload map[string]interface{}
				if err := json.Unmarshal(content, &payload); err == nil {
					phash, pitems := jsonrpc.String(payload["hash"]), int64(jsonrpc.Number(payload["items"]))
					if pid := jsonrpc.String(payload["id"]); pid == name {
						peer.seen = time.Now()
						if len(phash) == 40 && pitems > 0 {
							if phash != peer.hash {
								log.Info(map[string]interface{}{"id": id, "event": "peer", "peer": name, "hash": phash, "items": pitems})
							}
							peer.hash, peer.items = phash, pitems
						}
					} else {
						log.Warn(map[string]interface{}{"id": id, "event": "peer", "peer": name, "error": fmt.Sprintf("peer mismatch %s", pid)})
					}
				} else {
					log.Warn(map[string]interface{}{"id": id, "event": "peer", "peer": name, "error": fmt.Sprintf("%v", err)})
				}
			} else {
				log.Warn(map[string]interface{}{"id": id, "event": "peer", "peer": name, "error": fmt.Sprintf("%v", err)})
			}
		} else {
			log.Warn(map[string]interface{}{"id": id, "event": "peer", "peer": name, "error": fmt.Sprintf("%03d %s",
				response.StatusCode, http.StatusText(response.StatusCode))})
		}
		response.Body.Close()
	} else {
		log.Warn(map[string]interface{}{"id": id, "event": "peer", "peer": name, "error": fmt.Sprintf("%v", err)})
	}
}

// synchronize items from peers
func synchronize() {
	lpeers := map[string]*PEER{}
	lock.Lock()
	for name, peer := range peers {
		lpeers[name] = peer
	}
	lock.Unlock()
	for name, peer := range lpeers {
		if peer.hash != hash {
			client, remote := &http.Client{Timeout: 10 * time.Second, Transport: transport}, config.GetString("peers/"+name, "")
			if response, err := client.Get(remote + "/_detail"); err == nil {
				if content, err := ioutil.ReadAll(response.Body); err == nil && len(content) > 0 {
					var payload map[string]*ITEM
					if err := json.Unmarshal(content, &payload); err == nil {
						add, remove := map[string]*ITEM{}, map[string]*ITEM{}
						lock.RLock()
						for pkey, pitem := range payload {
							if items[pkey] == nil || (pitem.Hash != items[pkey].Hash && time.Now().Unix()-pitem.Seen < 10 && items[pkey].Modified < pitem.Modified) {
								add[pkey] = pitem
							}
							if items[pkey] != nil && pitem.Hash == items[pkey].Hash && time.Now().Unix()-pitem.Seen > 10 {
								remove[pkey] = pitem
							}
						}
						lock.RUnlock()
						for key, item := range add {
							if response, err := client.Get(remote + "/" + key); err == nil {
								if content, err := ioutil.ReadAll(response.Body); err == nil && len(content) > 0 {
									if fmt.Sprintf("%x", sha1.Sum(content)) == item.Hash {
										target, ok := root+"/"+key, true
										if _, err := os.Stat(target); err == nil && backup != "" {
											ok = false
											updated := fmt.Sprintf("%s/%s.updated.%d", backup, key, time.Now().UnixNano()/int64(time.Millisecond))
											os.MkdirAll(filepath.Dir(updated), 0755)
											if os.Rename(target, updated) == nil {
												ok = true
											}
										}
										if ok {
											os.MkdirAll(filepath.Dir(target), 0755)
											if ioutil.WriteFile(target, content, 0644) == nil {
												os.Chtimes(target, time.Unix(item.Modified, 0), time.Unix(item.Modified, 0))
												log.Info(map[string]interface{}{"id": id, "event": "add", "peer": name, "item": key})
											}
										}
									}
								}
								response.Body.Close()
							}
						}
						for key, _ := range remove {
							target, ok := root+"/"+key, true
							if _, err := os.Stat(target); err == nil && backup != "" {
								ok = false
								removed := fmt.Sprintf("%s/%s.removed.%d", backup, key, time.Now().UnixNano()/int64(time.Millisecond))
								os.MkdirAll(filepath.Dir(removed), 0755)
								if os.Rename(target, removed) == nil {
									ok = true
								}
							}
							if ok {
								if os.Remove(target) == nil {
									lock.Lock()
									delete(items, key)
									lock.Unlock()
									log.Info(map[string]interface{}{"id": id, "event": "remove", "peer": name, "item": key})
								}
							}
						}
						if len(add) > 0 || len(remove) > 0 {
							local()
						}
					}
				}
				response.Body.Close()
			}
		}
	}
}

// HTTP service handler
func handler(response http.ResponseWriter, request *http.Request) {
	var content []byte

	if request.Method != http.MethodGet {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if auth := strings.TrimSpace(config.GetString("auth", "")); auth != "" {
		if user, password, ok := request.BasicAuth(); ok {
			if auth != user+":"+password {
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
		} else {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	switch request.URL.Path {
	case "/_state":
		lock.RLock()
		content, _ = json.Marshal(map[string]interface{}{"id": id, "hash": hash, "items": len(items)})
		lock.RUnlock()
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
	case "/_detail":
		lock.RLock()
		content, _ = json.Marshal(items)
		lock.RUnlock()
		response.Header().Set("Content-Type", "application/json")
		response.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
	default:
		if content, _ = ioutil.ReadFile(root + request.URL.Path); content != nil && len(content) > 0 {
			response.Header().Set("Content-Type", "application/octet-stream")
			response.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		} else {
			response.WriteHeader(http.StatusNotFound)
			return
		}
	}
	response.Write(content)
}

// main program entry
func main() {
	var err error

	// parse configuration
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <configuration file>\n", filepath.Base(os.Args[0]))
		os.Exit(1)
	}
	if config, err = uconfig.New(os.Args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "configuration file syntax error: %s - aborting\n", err)
		os.Exit(2)
	}
	config.SetSeparator("/")
	log = ulog.New(config.GetString("log", "console()"))
	hostname, _ := fqdn.FQDN()
	id = config.GetString("id", hostname)
	root = strings.TrimSuffix(strings.TrimSpace(config.GetString("root", root)), "/")
	filter = strings.TrimSpace(config.GetString("filter", filter))
	if backup = strings.TrimSuffix(strings.TrimSpace(config.GetString("backup", backup)), "/"); backup != "" {
		os.MkdirAll(backup, 0755)
		ioutil.WriteFile(fmt.Sprintf("%s/.%s", backup, progname), []byte{}, 0644)
	}
	if config.GetBoolean("insecure", false) {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	log.Info(map[string]interface{}{"id": id, "event": "start", "version": version, "config": os.Args[1], "pid": os.Getpid(),
		"root": root, "filter": filter, "backup": backup, "peers": len(config.GetPaths("peers"))})

	// build local state every 3 seconds
	go func() {
		for range time.Tick(3 * time.Second) {
			local()
		}
	}()

	// synchronize items every 5 seconds
	go func() {
		for range time.Tick(5 * time.Second) {
			synchronize()
		}
	}()

	// poll peers states every 7 seconds
	go func() {
		for range time.Tick(7 * time.Second) {
			for _, path := range config.GetPaths("peers") {
				if name := strings.TrimPrefix(path, "peers/"); name != id {
					peer(name, strings.TrimSuffix(config.GetString(path, ""), "/"))
				}
			}
		}
	}()

	// expose local information through HTTP
	http.HandleFunc("/", handler)
	if parts := strings.Split(config.GetStringMatch("listen", "*:11170", `^.*?(:\d+)?((,[^,]+){2})?$`), ","); parts[0] != "_" {
		server := &http.Server{Addr: strings.TrimLeft(parts[0], "*"), ReadTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second}
		if len(parts) > 1 {
			loader := &dynacert.DYNACERT{Public: parts[1], Key: parts[2]}
			server.TLSConfig = dynacert.IntermediateTLSConfig(loader.GetCertificate)
			log.Info(map[string]interface{}{"id": id, "event": "listen", "listen": parts[0], "public": parts[1], "key": parts[2]})
			server.ListenAndServeTLS("", "")
		} else {
			log.Info(map[string]interface{}{"id": id, "event": "listen", "listen": parts[0]})
			server.ListenAndServe()
		}
	}
	select {}
}