# socks5
a simple SOCKS5 server



## example

```go
package main

import (
	"log"
	"sync"
	"time"

	"github.com/Doraemonkeys/socks5"
)

// curl --proxy socks5://admin:123456@localhost:1080 www.baidu.com
// curl --socks5 localhost:1080 www.baidu.com

func main() {
	users := map[string]string{
		"admin":    "123456",
	}
	var mutex sync.Mutex
    
	server := socks5.SOCKS5Server{
		IP:   "localhost",
		Port: 1080,
		Config: &socks5.Config{
			AuthMethod: socks5.MethodNoAuth,
			PasswordChecker: func(username, password string) bool {
				mutex.Lock()
				defer mutex.Unlock()
				wantPassword, ok := users[username]
				if !ok {
					return false
				}
				return wantPassword == password
			},
			TCPTimeout: 5 * time.Second,
		},
	}

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}
```

