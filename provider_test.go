package regfish_test

import (
	"context"
	"testing"
	"time"

	"os"

	"github.com/joho/godotenv"
	"github.com/libdns/libdns"
	"github.com/libdns/regfish"
	"github.com/stretchr/testify/assert"
)

var provider regfish.Provider
var test_zone = "example.com"
var test_name = "libdns-test"

func TestProviderFunction(t *testing.T) {
	err := godotenv.Load(".env")
	if err != nil {
		panic("Cannot open .env file")
	}

	provider = regfish.Provider{
		APIToken: os.Getenv("RF_API_KEY"),
	}

	t.Run("Testing GetRecords", func(t *testing.T) {
		result, err := provider.GetRecords(context.Background(), test_zone)
		assert.Nil(t, err)
		assert.NotNil(t, result)
	})

	records := []libdns.Record{{Name: test_name, Type: "A", Value: "10.250.1.1", TTL: time.Duration(60) * time.Second}}

	t.Run("Testing AppendRecords", func(t *testing.T) {
		result, err := provider.AppendRecords(context.Background(), test_zone, records)
		assert.Nil(t, err)
		assert.NotNil(t, result)
	})

	records = []libdns.Record{{Name: test_name, Type: "A", Value: "10.250.2.2", TTL: time.Duration(120) * time.Second}}

	t.Run("Testing SetRecords", func(t *testing.T) {
		result, err := provider.SetRecords(context.Background(), test_zone, records)
		assert.Nil(t, err)
		assert.NotNil(t, result)
	})

	t.Run("Testing DeleteRecords", func(t *testing.T) {
		// Set up mock data or environments as needed.
		result, err := provider.DeleteRecords(context.Background(), test_zone, records)
		assert.Nil(t, err)
		assert.NotNil(t, result)
	})
}
