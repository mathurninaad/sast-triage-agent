const express = require("express");
const db = require("./db");
const app = express();

function requireLogin(req, res, next) { next(); }

// findUser(req.params.id) in a comment is not a call
const label = "findUser(x) in a string is not a call";

const getUser = (req, res) => {
  res.json(db.findUser(req.params.id));
};

app.get("/users/:id", requireLogin, getUser);
app.post("/upload", handlers.upload);
