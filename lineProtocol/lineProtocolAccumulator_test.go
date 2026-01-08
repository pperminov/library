package lineProtocol

import (
	"testing"
	"time"

	libraryErrors "github.com/pperminov/library/errors"
	libraryNumbers "github.com/pperminov/library/numbers"
	libraryStrings "github.com/pperminov/library/strings"
	"github.com/stretchr/testify/require"
)

const defaultRandomStringLength = 6

func generateFields(amount int) map[string]any {
	for {
		m := make(map[string]any)
		for i := amount; i > 0; i-- {
			randomNumber, err := libraryNumbers.SimpleRand()
			libraryErrors.Panicer(err)
			m[libraryStrings.RandString(defaultRandomStringLength)] = int64(randomNumber)
		}
		if len(m) != amount {
			continue
		}
		return m
	}
}
func generateTags(amount int) map[string]string {
	for {
		m := make(map[string]string)
		for i := amount; i > 0; i-- {
			m[libraryStrings.RandString(defaultRandomStringLength)] = libraryStrings.RandString(defaultRandomStringLength)
		}
		if len(m) != amount {
			continue
		}
		return m
	}
}

func TestAccumulatorErrors(t *testing.T) {
	a := NewAccumulator()

	err := a.AddLine("", generateFields(1), generateTags(1), time.Now())
	require.Error(t, err)

	err = a.AddLine("m", generateFields(0), generateTags(1), time.Now())
	require.Error(t, err)

	result, err := LineProtocolParser(string(a.GetBytes()))
	require.NoError(t, err)
	require.Equal(t, len(result), 0)

	err = a.AddLine("m", generateFields(1), generateTags(1), time.Now())
	require.NoError(t, err)

	err = a.AddLine("m", generateFields(1), map[string]string{"someField": ""}, time.Now())
	require.Error(t, err)

	err = a.AddLine("m", map[string]any{"someField": 1}, generateTags(1), time.Now())
	require.Error(t, err)
}

func TestAccumulatorCorrectness(t *testing.T) {
	for i := 1; i > 0; i-- {
		fields := generateFields(666)
		tags := generateTags(666)
		a := NewAccumulator()
		timeToUse := time.Now()
		a.AddLine("measurement", fields, tags, timeToUse)
		data, err := LineProtocolParser(string(a.GetBytes()))
		require.NoError(t, err)
		require.True(t, compareTags(data[0].Tags, tags))
		require.True(t, compareIntegerFields(data[0].Fields, fields))
	}
}
