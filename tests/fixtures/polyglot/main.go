package main

import "net/http"

type Server struct{ db *DB }

func (s *Server) GetUser(w http.ResponseWriter, r *http.Request) {
	s.db.FindUser(r.URL.Query().Get("id"))
}

func main() {
	s := &Server{}
	http.HandleFunc("/users", s.GetUser)
}
