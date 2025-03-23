package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Time is a primitive of the time data type representing a duration in nanoseconds.
type Time time.Duration

// Calculates the nanosecond duration between the current time and the inputs
func newDuration(hour, min, sec, nsec int) Time {
	return Time(
		time.Duration(hour)*time.Hour +
			time.Duration(min)*time.Minute +
			time.Duration(sec)*time.Second +
			time.Duration(nsec)*time.Nanosecond,
	)
}

// NewTime is a constructor for Time and returns new Time.
func NewTime(hour, min, sec, nsec int) Time {
	return newDuration(hour, min, sec, nsec)
}

func (t *Time) setFromString(str string) {
	var h, m, s, n int
	fmt.Sscanf(str, "%02d:%02d:%02d.%09d", &h, &m, &s, &n)
	*t = newDuration(h, m, s, n)
}

func (t *Time) setFromTime(src time.Time) {
	*t = newDuration(src.Hour(), src.Minute(), src.Second(), src.Nanosecond())
}

// String implements fmt.Stringer interface.
func (t Time) String() string {
	if nsec := t.nanoseconds(); nsec > 0 {
		return fmt.Sprintf("%02d:%02d:%02d.%09d", t.hours(), t.minutes(), t.seconds(), nsec)
	} else {
		// omit nanoseconds unless any value is specified
		return fmt.Sprintf("%02d:%02d:%02d", t.hours(), t.minutes(), t.seconds())
	}
}

func (t Time) hours() int {
	return int(time.Duration(t).Truncate(time.Hour).Hours())
}

func (t Time) minutes() int {
	return int((time.Duration(t) % time.Hour).Truncate(time.Minute).Minutes())
}

func (t Time) seconds() int {
	return int((time.Duration(t) % time.Minute).Truncate(time.Second).Seconds())
}

func (t Time) nanoseconds() int {
	return int((time.Duration(t) % time.Second).Nanoseconds())
}

// MarshalJSON implements json.Marshaler to convert Time to json serialization.
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// UnmarshalJSON implements json.Unmarshaler to deserialize json data.
func (t *Time) UnmarshalJSON(data []byte) error {
	// ignore null
	if string(data) == "null" {
		return nil
	}
	t.setFromString(strings.Trim(string(data), `"`))
	return nil
}
