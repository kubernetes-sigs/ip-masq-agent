package interval

import (
	"fmt"
	"strconv"
	"strings"
)

type Interval struct {
	First int
	Last  int
}

func (i Interval) Size() int {
	return max(0, i.Last-i.First+1)
}

func (i Interval) String() string {
	if i.First < 0 || i.Last < i.First {
		return ""
	}
	if i.First == i.Last {
		return strconv.Itoa(i.First)
	}
	return fmt.Sprintf("%d-%d", i.First, i.Last)
}

func ParseInterval(s string) (Interval, error) {
	var i Interval

	p := strings.Split(s, "-")
	if len(p) > 2 {
		return i, fmt.Errorf("invalid interval %q", s)
	}

	v, err := strconv.Atoi(p[0])
	if err != nil {
		return i, err
	}
	i.First = v

	if len(p) == 1 {
		i.Last = v
		return i, nil
	}

	v, err = strconv.Atoi(p[1])
	if err != nil {
		return i, err
	}
	i.Last = v

	if i.First > i.Last {
		return i, fmt.Errorf("first is greater than last in %q", s)
	}
	return i, nil
}

type Intervals []Interval

func (i Intervals) Size() int {
	var size int
	for _, j := range i {
		size += j.Size()
	}
	return size
}

func ParseIntervals(s string) (Intervals, error) {
	var is Intervals

	for _, p := range strings.Split(s, ",") {
		i, err := ParseInterval(p)
		if err != nil {
			return is, err
		}

		is = append(is, i)
	}

	return is, nil
}
