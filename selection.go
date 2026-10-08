package main

import "fmt"

func eliminationReason(samples []Sample, c Config) string {
	if len(samples) == 0 {
		return ""
	}
	last := samples[len(samples)-1]
	if c.MaxTTFBMs > 0 && last.Usable && last.TTFBMs != nil && *last.TTFBMs > float64(c.MaxTTFBMs) {
		return fmt.Sprintf("TTFB exceeds %dms", c.MaxTTFBMs)
	}
	passed := 0
	for _, s := range samples {
		if s.Usable && s.TTFBMs != nil {
			passed++
		}
	}
	if float64(passed+c.SamplesPerIP-len(samples))/float64(c.SamplesPerIP) < c.MinSuccessRate {
		return "remaining samples cannot meet minSuccessRate"
	}
	return ""
}
