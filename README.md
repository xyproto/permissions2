permissions
===========

Middleware for Negroni for keeping track of users.
Uses secure cookies and stores user information in a Redis database. 

Suitable for running a local Redis server and managing public pages, pages that are available for logged in users and pages that are available for logged in administrators.

Supports registration and confirmation via generated confirmation codes.

Tries to keep things simple.

See examples/main.go for an example.

MIT Licensed

Alexander Rødseth 2014
