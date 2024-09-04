# BGGP5 - @mebeim - Go

Run with `go run file.go` except for special cases (see notes below). Tested
with Go 1.22.3 linux/amd64 on Debian 12.

| File                                                           | Source size | Notes                                             |
|----------------------------------------------------------------|-------------|---------------------------------------------------|
| [`cgo_system_curl_env_trick.go`](cgo_system_curl_env_trick.go) | 63 bytes    | Needs special setup (see below). Uses [cgo][cgo]. |
| [`cgo_system_curl_pwd_trick.go`](cgo_system_curl_pwd_trick.go) | 76 bytes    | Needs special setup (see below). Uses [cgo][cgo]. |
| [`cgo_system_curl.go`](cgo_system_curl.go)                     | 84 bytes    | Needs `curl` installed. Uses [cgo][cgo].          |
| [`plain.go`](plain.go)                                         | 136 bytes   | Needs `curl` installed.                           |

Note that these files all miss the final newline character. This is intended to
save space!

Important notes for some special cases:

- **`cgo_system_curl_env_trick.go`**:

  This version needs a command set in the `A` environment variable and simply
  executes `system("$A");`. Lame, I know, but apparently still a valid BGGP entry!

  ```bash
  A='curl https://binary.golf/5/5' go run cgo_system_curl_env_trick.go
  ```


- **`cgo_system_curl_pwd_trick.go`**:

  This version needs to run with `/binary.golf/5/5` as the current working
  directory because it runs `system("curl https:$PWD")`. Still lame, I know,
  but apparently still a valid BGGP entry!

  ```bash
  sudo mkdir -p /binary.golf/5/5
  sudo chown -R $USER:$USER /binary.golf

  cp cgo_system_curl_pwd_trick.go /binary.golf/5/5
  cd /binary.golf/5/5
  go run cgo_system_curl_pwd_trick.go
  ```

---

*Copyright &copy; 2024 Marco Bonelli (@mebeim). Licensed under the MIT License.*


[cgo]: https://go.dev/wiki/cgo
