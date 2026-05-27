package profiler

import (
	"errors"
	"math"
)

// score ranks a FlowMetrics on stability (low CoV), volume, and endpoint diversity.
// Returns a composite score in [0,1]; higher is better.
func score(f FlowMetrics) float64 {
	sizeCoV := coefVar(f.PktSizes)
	iatCoV := coefVar(f.IATs)
	stability := 1.0 / (1.0 + sizeCoV + iatCoV)

	volume := 0.0
	if f.TotalBytes > 0 {
		volume = logScale(float64(f.TotalBytes), 1e6)
	}

	diversity := float64(len(f.Endpoints)) / 10.0
	if diversity > 1 {
		diversity = 1
	}

	return 0.5*stability + 0.35*volume + 0.15*diversity
}

// logScale returns a log-normalised value in [0,1] relative to ref.
// Uses log1p to compress large ranges so volume doesn't dominate the score.
func logScale(x, ref float64) float64 {
	if x <= 0 || ref <= 0 {
		return 0
	}
	v := math.Log1p(x) / math.Log1p(ref)
	if v > 1 {
		return 1
	}
	return v
}

// selectBest returns the FlowMetrics with the highest score.
// Returns an error if flows is empty.
func selectBest(flows []FlowMetrics) (FlowMetrics, error) {
	if len(flows) == 0 {
		return FlowMetrics{}, errors.New("selectBest: no flows observed during capture window")
	}
	best := flows[0]
	bestScore := score(flows[0])
	for _, f := range flows[1:] {
		if s := score(f); s > bestScore {
			best = f
			bestScore = s
		}
	}
	return best, nil
}
