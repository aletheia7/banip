[![](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/aletheia7/banip) 

### Installation
- Rapid development is happening and docs are on the way.

```
apt-get install libmnl-dev libnfnetlink-dev
git clone --recursive https://github.com/aletheia7/banip.git
go generate vendor/github.com/aletheia7/nfqueue/nfqueue.go
```
  - add a line in nftables:
  ```
  ct state new tcp dport { ? } queue num 77 bypass
  ```

#### License 

Use of this source code is governed by a BSD-2-Clause license that can be found
in the LICENSE file.

<a href="https://opensource.org/"><img src="img/osi_logo_100X133_90ppi_0.png"></img></a>
