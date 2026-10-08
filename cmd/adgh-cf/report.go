package main

import (
	"math"
	"sort"
)

type Summary struct {
	IP               string   `json:"ip"`
	SampleCount      int      `json:"sampleCount"`
	SuccessRate      float64  `json:"successRate"`
	Eligible         bool     `json:"eligible"`
	MedianTTFBMs     *float64 `json:"medianTtfbMs"`
	P95TTFBMs        *float64 `json:"p95TtfbMs"`
	Samples          []Sample `json:"samples"`
	EliminatedReason string   `json:"eliminatedReason,omitempty"`
}

func summarize(ip string, samples []Sample, threshold float64) Summary {
	r := Summary{IP: ip, SampleCount: len(samples), Samples: samples}
	times := []float64{}
	for _, s := range samples {
		if s.Usable && s.TTFBMs != nil {
			times = append(times, *s.TTFBMs)
		}
	}
	if len(samples) > 0 {
		r.SuccessRate = float64(len(times)) / float64(len(samples))
		r.Eligible = r.SuccessRate >= threshold
	}
	sort.Float64s(times)
	if len(times) > 0 {
		mid := len(times) / 2
		v := times[mid]
		if len(times)%2 == 0 {
			v = (times[mid-1] + times[mid]) / 2
		}
		r.MedianTTFBMs = &v
	}
	if len(times) >= 20 {
		v := times[int(math.Ceil(float64(len(times))*.95))-1]
		r.P95TTFBMs = &v
	}
	return r
}

func rank(results []Summary) []Summary {
	r := []Summary{}
	for _, s := range results {
		if s.Eligible {
			r = append(r, s)
		}
	}
	metric := func(s Summary) float64 {
		if s.P95TTFBMs != nil {
			return *s.P95TTFBMs
		}
		if s.MedianTTFBMs != nil {
			return *s.MedianTTFBMs
		}
		return math.Inf(1)
	}
	sort.SliceStable(r, func(i, j int) bool {
		if r[i].SuccessRate != r[j].SuccessRate {
			return r[i].SuccessRate > r[j].SuccessRate
		}
		return metric(r[i]) < metric(r[j])
	})
	return r
}
