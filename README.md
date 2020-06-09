# SOCKS5

Package socks5 provides SOCKS5 client and server implementations.

## Feature

* No Authentication mode
* UserName/Password authentication
* Support CONNECT command



## Example

Create a SOCKS5 proxy server 
```go
socks5.ListenAndServe("tcp", "127.0.0.1:8888")
```


Create a SOCKS5 client and Dial
```go
client, err := socks5.NewClient("127.0.0.1:8888")
if err != nil {
    panic(err)
}
conn, err := client.Dial("tcp", "google.com:443")
if err != nil {
    panic(err)
}
defer conn.Close()
// ......
```

Create a SOCKS5 proxy server with username/password
```go
pw := make(map[string]string)
pw["username"] = "password"
socks5.ListenAndServeWithAuth("tcp", "127.0.0.1:8888", pw)
```

Create a SOCKS5 client and Dial with username/password
```go
client, err := socks5.NewClientWithAuth("127.0.0.1:8888", "username", "password")
if err != nil {
    panic(err)
}
conn, err := client.Dial("tcp", "google.com:443")
if err != nil {
    panic(err)
}
defer conn.Close()
// ......
```

## TODO

* Design Logging API
* Support UDP ASSOCIATE command
* Support BIND command
## References

[RFC 1928](https://tools.ietf.org/html/rfc1928)
[RFC 1929](https://tools.ietf.org/html/rfc1929)
[golang.org/x/net/internal/socks](https://github.com/golang/net/tree/master/internal/socks)
[golang.org/x/net/internal/sockstest](https://github.com/golang/net/tree/master/internal/sockstest)
[armon/go-socks5](https://github.com/armon/go-socks5)


## License

This software is licensed under the MIT License. 