package auth

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"math/big"
	"strconv"
)

type Token string

type OTP struct {
	Token  Token
	UID    UID
	Expiry Time
}

type TokenMaker interface {
	GenerateToken() (Token, error)
	CreateOTP(uid UID, expiry Time) error
	ReadOTP(token Token) (UID, error)
}

/**
 * Generates a random 32 bit floating number between 0 and 1.
 * The function uses the crypto/rand package to generate 23 random bits for the mantissa
 */
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

/**
 * Generates a random 64 bit floating number between 0 and 1.
 * The function uses the crypto/rand package to generate 52 random bits for the mantissa
 */
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

/*
 * Generates a random integer value of arbitrary size that is less than the given max value.
 * The function uses a rejection sampling technique based on comparing the random value after it is
 * bit shifted with the max value.
 */
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

func RandomString(enc *EncodingScheme, strLen uint, charSubset *string) (string, error) {
	var base = B64
	var err error = nil
	var result = ""

	if enc != nil {
		base = *enc
	}

	switch base {
	case B10:
		byteLen := int(math.Ceil(float64(strLen*4) / 8))
		bytes := make([]byte, byteLen)

		for i := 0; i < byteLen; i++ {
			strBytes := []byte(strconv.Itoa(int(RandomUint32(10))))

			for j := 0; j < len(strBytes) && j <= i; j++ {
				bytes[i] = strBytes[j]
			}
			i = len(strBytes) - 1
			if i <= 0 {
				break
			}
		}
		println("Bytle Length: ", byteLen)
		println(bytes)
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
			result = base32.NewEncoding(*charSubset).EncodeToString(bytes)
		} else {
			result = base32.StdEncoding.EncodeToString(bytes)
		}
	case B64:
		byteLen := int(math.Ceil(float64(strLen*6) / 8))
		bytes := make([]byte, byteLen)
		_, err = rand.Read(bytes)
		if charSubset != nil {
			result = base64.NewEncoding(*charSubset).EncodeToString(bytes)
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
