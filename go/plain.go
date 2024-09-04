package main
import("fmt";h"net/http";"io")
func main(){r,_:=h.Get("http://binary.golf/5/5");s,_:=io.ReadAll(r.Body);fmt.Printf("%s",s)}