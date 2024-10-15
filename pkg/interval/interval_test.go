package interval

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIntervalSize(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval Interval
		want     int
	}{
		{
			name: "standard",
			interval: Interval{
				First: 42,
				Last:  44,
			},
			want: 3,
		},
		{
			name: "single",
			interval: Interval{
				First: 42,
				Last:  42,
			},
			want: 1,
		},
		{
			name: "negative",
			interval: Interval{
				First: 44,
				Last:  42,
			},
			want: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.interval.Size(); got != tc.want {
				t.Errorf("Size = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestIntervalString(t *testing.T) {
	for _, tc := range []struct {
		name     string
		interval Interval
		want     string
	}{
		{
			name: "standard",
			interval: Interval{
				First: 42,
				Last:  44,
			},
			want: "42-44",
		},
		{
			name: "single",
			interval: Interval{
				First: 42,
				Last:  42,
			},
			want: "42",
		},
		{
			name: "zero",
			interval: Interval{
				First: 0,
				Last:  0,
			},
			want: "0",
		},
		{
			name: "zero-range",
			interval: Interval{
				First: 0,
				Last:  42,
			},
			want: "0-42",
		},
		{
			name: "negative",
			interval: Interval{
				First: -1,
				Last:  1,
			},
			want: "",
		},
		{
			name: "reverse",
			interval: Interval{
				First: 44,
				Last:  42,
			},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.interval.String(); got != tc.want {
				t.Errorf("String = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseInterval(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   string
		want    Interval
		wantErr bool
	}{
		{
			name:  "standard",
			input: "42-44",
			want: Interval{
				First: 42,
				Last:  44,
			},
		},
		{
			name:  "single",
			input: "42",
			want: Interval{
				First: 42,
				Last:  42,
			},
		},
		{
			name:  "single-range",
			input: "42-42",
			want: Interval{
				First: 42,
				Last:  42,
			},
		},
		{
			name:    "space",
			input:   "42 - 44",
			wantErr: true,
		},
		{
			name:    "multiple",
			input:   "42-43-44",
			wantErr: true,
		},
		{
			name:    "invalid",
			input:   "4x",
			wantErr: true,
		},
		{
			name:    "invalid-first",
			input:   "4x-44",
			wantErr: true,
		},
		{
			name:    "invalid-last",
			input:   "42-4x",
			wantErr: true,
		},
		{
			name:    "missing-first",
			input:   "-44",
			wantErr: true,
		},
		{
			name:    "missing-last",
			input:   "42-",
			wantErr: true,
		},
		{
			name:    "negative",
			input:   "42-41",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseInterval(tc.input)
			if err != nil && !tc.wantErr {
				t.Fatalf("Got unexpected error: %v", err)
			}
			if err == nil && tc.wantErr {
				t.Fatalf("Want error; did not get")
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Got unexpected Interval (-want +got):\n%s", diff)
			}
		})
	}
}

func TestIntervalsSize(t *testing.T) {
	for _, tc := range []struct {
		name      string
		intervals Intervals
		want      int
	}{
		{
			name: "standard",
			intervals: Intervals{
				{
					First: 42,
					Last:  44,
				},
				{
					First: 82,
					Last:  84,
				},
			},
			want: 6,
		},
		{
			name: "single",
			intervals: Intervals{
				{
					First: 42,
					Last:  44,
				},
			},
			want: 3,
		},
		{
			name:      "empty",
			intervals: Intervals{},
			want:      0,
		},
		{
			name:      "nil",
			intervals: nil,
			want:      0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.intervals.Size(); got != tc.want {
				t.Errorf("Size = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestParseIntervals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		input   string
		want    Intervals
		wantErr bool
	}{
		{
			name:  "standard",
			input: "42-44,80",
			want: Intervals{
				{
					First: 42,
					Last:  44,
				},
				{
					First: 80,
					Last:  80,
				},
			},
		},
		{
			name:  "separate",
			input: "42,43,44",
			want: Intervals{
				{
					First: 42,
					Last:  42,
				},
				{
					First: 43,
					Last:  43,
				},
				{
					First: 44,
					Last:  44,
				},
			},
		},
		{
			name:  "reverse",
			input: "43,42",
			want: Intervals{
				{
					First: 43,
					Last:  43,
				},
				{
					First: 42,
					Last:  42,
				},
			},
		},
		{
			name:  "reverse-range",
			input: "80-88,42-44",
			want: Intervals{
				{
					First: 80,
					Last:  88,
				},
				{
					First: 42,
					Last:  44,
				},
			},
		},
		{
			name:  "overlap",
			input: "42-44,42-43",
			want: Intervals{
				{
					First: 42,
					Last:  44,
				},
				{
					First: 42,
					Last:  43,
				},
			},
		},
		{
			name:  "single",
			input: "42",
			want: Intervals{
				{
					First: 42,
					Last:  42,
				},
			},
		},
		{
			name:  "single-range",
			input: "42-42",
			want: Intervals{
				{
					First: 42,
					Last:  42,
				},
			},
		},
		{
			name:    "space",
			input:   "42, 43, 44",
			wantErr: true,
		},
		{
			name:    "multiple",
			input:   "42-43-44",
			wantErr: true,
		},
		{
			name:    "invalid",
			input:   "4x",
			wantErr: true,
		},
		{
			name:    "negative",
			input:   "42-41",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseIntervals(tc.input)
			if err != nil && !tc.wantErr {
				t.Fatalf("Got unexpected error: %v", err)
			}
			if err == nil && tc.wantErr {
				t.Fatalf("Want error; did not get")
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Got unexpected Intervals (-want +got):\n%s", diff)
			}
		})
	}
}
