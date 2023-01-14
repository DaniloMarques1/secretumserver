package database

import (
	"context"
	"os"
	"sync"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	once    sync.Once
	client  *mongo.Client
	connErr error
)

func GetDatabaseConnection() (*mongo.Client, error) {
	once.Do(func() {
		uri := os.Getenv("DATABASE_URI")
		client, connErr = mongo.Connect(
			context.Background(),
			options.Client().ApplyURI(uri),
		)
		if connErr != nil {
			return
		}
		if connErr = client.Ping(context.Background(), nil); connErr != nil {
			return
		}
	})

	if connErr != nil {
		return nil, connErr
	}

	return client, nil
}
