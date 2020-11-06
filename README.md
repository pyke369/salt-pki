`salt-pki` is a [SaltStack](https://www.saltstack.com/) PKI synchronization daemon written in Go, suitable for
[multimasters](https://docs.saltstack.com/en/latest/topics/tutorials/multimaster.html) configurations. Data
replication can be configured in full-mesh (all peers referencing each others) or bespoke mode (some peers
acting as "central hubs" for others), all updates are historized by default.

### _Build & Packaging_
You need to install a recent version of the [Golang](https://golang.org/dl/) compiler (>= 1.15) and the GNU
[make](https://www.gnu.org/software/make) utility to build the `salt-pki` binary. Once these requirements are
fulfilled, clone the `salt-pki` Github repository locally:
```
$ git clone https://github.com/pyke369/salt-pki
```
and type:
```
$ make
```
This will take care of building everything. You may optionally produce a Debian binary package by typing:
```
$ make deb
```
(the [devscripts](https://packages.debian.org/fr/sid/devscripts) package needs to be installed for this last
command to work)

### _Configuration_
Software configuration is performed through a unique file (`/etc/salt-pki.conf` by default), with sensible
default values specified in the provided example document:
```
# listen   = "*:11170"
# auth     = ""
# insecure = false
# log      = "console()"
# root     = "/etc/salt/pki/master"
# filter   = "minions*"
# backup   = "/etc/salt/pki/master/backup"
# id       = "<local-fqdn>"
# peers
# {
#     <peer-id> = "<peer-url>"
# }
```
Available options are described below:

- `listen` (default `"*:11170"`): the network address the daemon listens to for requests from peers. It is highly
recommended to activate HTTPS transport using the following syntax: `"*:<port>,<certificate-path>,<key-path>"`,
for instance:
```
listen = "*:11170,/etc/ssl/certs/server-cert.pem,/etc/ssl/private/server-key.pem"
```

- `auth` (default `<none>`): the credentials (in `login:password` form) used to authorize requests from other peers.
It is highly recommended to activate credentials checking for security reasons (and use the
`https://<login>:<password>@<hostname>:<port>` url form in the peers section below).

- `insecure` (default `false`): whether the daemon should trust responses from non-verified HTTPS peers or not.
This is a major security risk to circumvent TLS certificates validation and changing this option default value
is not recommended.

- `log` (default `"console()"`): where to log the daemon activity (on standard error by default, but this can be
modified to use files or syslog, see [here](https://github.com/pyke369/golang-support/tree/master/ulog) for more
information). Logs are structured in JSON format, for instance:
```
2019-11-17 10:55:01 INFO {"backup":"/etc/salt/pki/master/backup","config":"/etc/salt-pki.conf","event":"start","filter":"minions*","id":"master-01","peers":10,"pid":91777,"root":"/etc/salt/pki/master","version":"1.0.0"}
2019-11-17 10:55:01 INFO {"event":"listen","id":"master-01","listen":"*:11170"}
2019-11-17 10:55:04 INFO {"event":"local","hash":"da39a3ee5e6b4b0d3255bfef95601890afd80709","id":"master-01","items":2763}
...
```

- `root` (default `"/etc/salt/pki/master"`): the directory to expose and synchronize with other configured peers.

- `filter` (default `"minions*"`): an optional filter to only select appropriate files and sub-directories from the
`root` directory above. This is by default all minions keys in their different "states" (accepted, pending, rejected,
...) on each saltmaster.

- `backup` (default `"/etc/salt/pki/master/backup"`): the directory where the previous versions of updated & removed
files are saved before applying modifications triggered by synchronization with peers. No backup will take place if
this option is set to empty (not a recommended setting for tracability reasons). Overwritten files will be suffixed
with `.updated.<ms-epoch>`, whereas deleted files will be suffixed with `.removed.<ms-epoch>`. 

- `id` (default `"<local-fqdn>"`): the local instance identifier (auto-defaults to the local fully-qualified hostname).

- `peers` (default `<empty>`): the list of peers to synchronyze from, in the `<id> = <url>` form. Identifiers may be
any string (including dot-separated IP addresses or hostames), and urls must include the protocol scheme, credentials
(if used) and remote TCP port. The peer referenced by the `ìd` option above is automatically filtered-out of the peers
list before attempting synchronization (to avoid synchronization loops). An example of a `peers` section is given below:
```
id = master2
peers
{
    master1 = "https://login:password@master1.domain.com:11170"
    master2 = "http://master2.domain.com:11170"
    master3 = "https://master3.domain2.com:21170"
}
```

### _Performances_
In a typical multimasters configuration with 10 to 20 saltmasters and 5.000 to 10.000 connected minions, changes will
converge in less than 10 seconds on all saltmasters. Your mileage may vary (especially if network latency happens to
be high between saltmasters).

### _License_
MIT - Copyright (c) 2019 Pierre-Yves Kerembellec
