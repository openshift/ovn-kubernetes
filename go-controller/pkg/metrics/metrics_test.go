package metrics

import (
	"reflect"
	"testing"
)

func Test_parseStopwatchShowOutput(t *testing.T) {
	tests := []struct {
		name                string
		stopwatchShowOutput string
		want                map[string]int
		wantErr             bool
	}{
		{
			name: "should return all metrics",
			stopwatchShowOutput: `Statistics for 'ovnnb_db_run'
  Total samples: 3618
  Maximum: 208 msec
  Minimum: 0 msec
  95th percentile: 52.887067 msec
  Short term average: 22.548798 msec
  Long term average: 26.117126 msec
Statistics for 'ovn-northd-loop'
  Total samples: 6269
  Maximum: 29999 msec
  Minimum: 0 msec
  95th percentile: 7726.066210 msec
  Short term average: 7778.877120 msec
  Long term average: 2740.125211 msec
Statistics for 'ovnsb_db_run'
  Total samples: 5923
  Maximum: 9 msec
  Minimum: 0 msec
  95th percentile: 0.970497 msec
  Short term average: 0.000139 msec
  Long term average: 0.136613 msec`,
			want: map[string]int{
				"ovnnb_db_run":    3618,
				"ovn-northd-loop": 6269,
				"ovnsb_db_run":    5923,
			},
			wantErr: false,
		},
		{
			name: "should return all metrics, even if 'Total samples' is not on first",
			stopwatchShowOutput: `Statistics for 'ovnnb_db_run'
  Maximum: 208 msec
  Minimum: 0 msec
  95th percentile: 52.887067 msec
  Total samples: 3618
  Short term average: 22.548798 msec
  Long term average: 26.117126 msec
Statistics for 'ovn-northd-loop'
  Total samples: 6269
  Maximum: 29999 msec
  Minimum: 0 msec
  95th percentile: 7726.066210 msec
  Short term average: 7778.877120 msec
  Long term average: 2740.125211 msec`,
			want: map[string]int{
				"ovnnb_db_run":    3618,
				"ovn-northd-loop": 6269,
			},
			wantErr: false,
		},
		{
			name: "should be able to parse only one metric",
			stopwatchShowOutput: `Statistics for 'ovnnb_db_run'
  Maximum: 208 msec
  Minimum: 0 msec
  95th percentile: 52.887067 msec
  Total samples: 3618
  Short term average: 22.548798 msec
  Long term average: 26.117126 msec`,
			want: map[string]int{
				"ovnnb_db_run": 3618,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseStopwatchShowOutput(tt.stopwatchShowOutput)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseStopwatchShowOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseStopwatchShowOutput() = %v, want %v", got, tt.want)
			}
		})
	}
}
