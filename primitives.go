package auth

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
	"time"
)

// Time is an alias of the time data type representing a point in time based on the unix epoch time.
type Time time.Time

// Time string represented by the output of t.UTC().Format(time.UnixDate)
type UTCTimeString string

// Time is a primitive of the time data type representing a duration in nanoseconds.
// Durations are represented as an int64 value. Therefore the maximum value represents 290years
type Duration time.Duration

// Calculates the nanosecond duration between the current time and the inputs
func makeDuration(hour, min, sec, nsec int) Duration {
	return Duration(
		time.Duration(hour)*time.Hour +
			time.Duration(min)*time.Minute +
			time.Duration(sec)*time.Second +
			time.Duration(nsec)*time.Nanosecond,
	)
}

// NewDuration is a constructor for Duration and returns new Duration.
func NewDuration(hour, min, sec, nsec int) Duration {
	return makeDuration(hour, min, sec, nsec)
}

func (t *Duration) setFromString(str string) {
	var h, m, s, n int
	fmt.Sscanf(str, "%02d:%02d:%02d.%09d", &h, &m, &s, &n)
	*t = makeDuration(h, m, s, n)
}

func (t *Duration) setFromTime(src time.Time) {
	*t = makeDuration(src.Hour(), src.Minute(), src.Second(), src.Nanosecond())
}

// String implements fmt.Stringer interface.
func (t Duration) String() string {
	if nsec := t.nanoseconds(); nsec > 0 {
		return fmt.Sprintf("%02d:%02d:%02d.%09d", t.hours(), t.minutes(), t.seconds(), nsec)
	} else {
		// omit nanoseconds unless any value is specified
		return fmt.Sprintf("%02d:%02d:%02d", t.hours(), t.minutes(), t.seconds())
	}
}

func (t Duration) hours() int {
	return int(time.Duration(t).Truncate(time.Hour).Hours())
}

func (t Duration) minutes() int {
	return int((time.Duration(t) % time.Hour).Truncate(time.Minute).Minutes())
}

func (t Duration) seconds() int {
	return int((time.Duration(t) % time.Minute).Truncate(time.Second).Seconds())
}

func (t Duration) nanoseconds() int {
	return int((time.Duration(t) % time.Second).Nanoseconds())
}

// MarshalJSON implements json.Marshaler to convert Time to json serialization.
func (t Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// UnmarshalJSON implements json.Unmarshaler to deserialize json data.
func (t *Duration) UnmarshalJSON(data []byte) error {
	// ignore null
	if string(data) == "null" {
		return nil
	}
	t.setFromString(strings.Trim(string(data), `"`))
	return nil
}

// Generates a random 32 bit floating number between 0 and 1.
// The function uses the crypto/rand package to generate 23 random bits for the mantissa
func RandomFloat32() float32 {
	bytes := make([]byte, 3)
	rand.Read(bytes)
	bytes = append(make([]byte, 1), bytes...) // prepend 1 byte as float32 requires 4 bytes
	// TODO: double check the correct bit mask for the sign & exponent part
	// sign | exponent | mantissa
	// 1 bit | 8  bit | 23 bit
	// 0b0 | 0b01111111 | 0b00000000000000000000000
	// set exponent and sign part to 0b00111111
	bytes[0] = 0x3f // 63
	//bytes[1] |= 0x80 // 128
	return math.Float32frombits(binary.BigEndian.Uint32(bytes)) - 1
}

// Generates a random 64 bit floating number between 0 and 1.
// The function uses the crypto/rand package to generate 52 random bits for the mantissa
func RandomFloat64() float64 {
	bytes := make([]byte, 7)
	rand.Read(bytes)
	bytes = append(make([]byte, 1), bytes...) // prepend 1 byte as float64 requires 8 bytes
	// sign | exponent | mantissa
	// 1 bit | 11  bit | 52 bit
	// set exponent part to 0b01111111111
	bytes[0] = 0x3f  // 63
	bytes[1] |= 0xf0 // 240
	return math.Float64frombits(binary.BigEndian.Uint64(bytes)) - 1
}

// Generates a random unsigned 32bit integer between [0, max).
// `max` should not be a very large number.
func RandomUint32(max uint32) uint32 {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	randUint32 := binary.BigEndian.Uint32(bytes) // Convert bytes to uint32
	// Use modulo to limit the value to the range [0, max)
	// Note: This may introduce a bias if max is not a power of 2.
	return randUint32 % max
}

// Generates a random unsigned 32bit integer between [0, max).
// `max` should not be a very large number.
func RandomUint64(max uint64) uint64 {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	randUint64 := binary.BigEndian.Uint64(bytes) // Convert bytes to uint64
	// Use modulo to limit the value to the range [0, max)
	// Note: This may introduce a bias if max is not a power of 2.
	return randUint64 % max
}

// Generates a random integer value of arbitrary size that is less than the given max
// value. The function uses a rejection sampling technique based on comparing
// the random value after it is bit shifted with the max value.
func RandomInteger(max *big.Int) *big.Int {
	randInt := new(big.Int)
	shift := max.BitLen() % 8
	bytes := make([]byte, (max.BitLen()/8)+1)
	rand.Read(bytes)
	if shift != 0 {
		bytes[0] &= (1 << shift) - 1
	}
	randInt.SetBytes(bytes)
	for randInt.Cmp(max) >= 0 {
		rand.Read(bytes)
		if shift != 0 {
			bytes[0] &= (1 << shift) - 1
		}
		randInt.SetBytes(bytes)
	}
	return randInt
}

type EncodingScheme string

const (
	HEX EncodingScheme = "hex"
	B32 EncodingScheme = "base32"
	B64 EncodingScheme = "base64"
	B10 EncodingScheme = "base10"
)

// Generates either a base10, 16, 32 or 64 encoded string of the specified length.
// The charSubset parameter is used when the encoding scheme is base32 or base64.
// It allows the user to specify a custom character set for the encoding.
// If charSubset is nil, the default encoding scheme will be used.
func RandomString(enc *EncodingScheme, strLen uint, charSubset *string) (string, error) {
	var base = B64
	var err error = nil
	var result = ""

	if enc != nil {
		base = *enc
	}

	switch base {
	case B10:
		byteLen := int(strLen)
		bytes := make([]byte, byteLen)

		for i := range byteLen {
			r := RandomUint32(10)
			strBytes := fmt.Appendf(nil, "%d", r)
			b := strBytes[0]
			//println(len(strBytes))
			//fmt.Printf("%d:0x%X ", r, b)
			bytes[i] = b
		}
		result = string(bytes)
	case HEX:
		byteLen := int(math.Ceil(float64(strLen*4) / 8))
		bytes := make([]byte, byteLen)
		_, err = rand.Read(bytes)
		result = hex.EncodeToString(bytes)
	case B32:
		byteLen := int(math.Ceil(float64(strLen*5) / 8))
		bytes := make([]byte, byteLen)
		_, err = rand.Read(bytes)
		if charSubset != nil {
			result = base32.NewEncoding(*charSubset).WithPadding(base32.NoPadding).EncodeToString(bytes)
		} else {
			result = base32.StdEncoding.EncodeToString(bytes)
		}
	case B64:
		byteLen := int(math.Ceil(float64(strLen*6) / 8))
		bytes := make([]byte, byteLen)
		_, err = rand.Read(bytes)
		if charSubset != nil {
			result = base64.NewEncoding(*charSubset).WithPadding(base64.NoPadding).
				EncodeToString(bytes)
		} else {
			result = base64.URLEncoding.EncodeToString(bytes)
		}
	default:
		return result, errors.New("unsupported encoding scheme or character subset")
	}

	if err != nil {
		return result, errors.New("unable to generate random bytes")
	}

	return result, err
}

// Digest is a primitive of the string data type representing a hash digest.
type Digest string

// Key is a primitive of the string data type representing a secret key.
type Key string

// KeyPair is a struct that contains a private key and a public key.
type KeyPair struct {
	PrivateKey Key
	PublicKey  Key
}

// GenerateSecret generates a random secret key of the specified size in bytes.
func GenerateSecret(keySize uint) (Key, error) {
	bytes := make([]byte, keySize)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return Key(hex.EncodeToString(bytes)), nil
}

// Generic event data structure
// The event structure can be used to represent the occurence of any event in a system.
// It contains an ID, a timestamp, a type, and data associated with the event.
// The ID is a unique identifier for the event.
// The timestamp is the time when the event occurred.
// The type is a string that represents the category, topic, or channel of an event.
// The data is an interface that can hold any type of data associated with the event.
type Event struct {
	ID        string `json:"id"`
	Timestamp Time   `json:"timestamp"`
	Type      string `json:"type"`
	Data      any    `json:"data"`
}
