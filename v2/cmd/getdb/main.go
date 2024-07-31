package main

import (
	"fmt"
	"github.com/gomodule/redigo/redis"
	"github.com/xyproto/permissions2/v2"
)

func main() {
	perm, err := permissions.New2()
	if err != nil {
		fmt.Println("Could not open Redis database")
		return
	}
	ustate := perm.UserState()

	// A bit of checking is needed, since the database backend is interchangeable
	pustate, ok := ustate.(*permissions.UserState)
	if !ok {
		fmt.Println("Not using the Redis database backend")
		return
	}

	// Convert from a simpleredis.ConnectionPool to a redis.Pool
	redisPool := redis.Pool(*pustate.Pool())
	fmt.Printf("Redis pool: %v (%T)\n", redisPool, redisPool)

	// Get the Redis connection as well
	redisConnection := redisPool.Get()
	fmt.Printf("Redis connection: %v (%T)\n", redisConnection, redisConnection)
}
