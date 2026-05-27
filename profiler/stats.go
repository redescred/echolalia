package profiler

import "math"

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

func stddev(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	m := mean(xs)
	var variance float64
	for _, x := range xs {
		d := x - m
		variance += d * d
	}
	return math.Sqrt(variance / float64(len(xs)-1))
}

func coefVar(xs []float64) float64 {
	m := mean(xs)
	if m == 0 {
		return 0
	}
	return stddev(xs) / m
}

// aicShape fits exponential vs normal to xs and returns "exponential" or "normal".
// Uses AIC: AIC = 2k - 2*ln(L). Lower AIC wins.
func aicShape(xs []float64) string {
	if len(xs) < 2 {
		return "exponential"
	}
	m := mean(xs)
	if m <= 0 {
		return "exponential"
	}
	s := stddev(xs)

	// Log-likelihood under exponential(lambda=1/mean)
	lambda := 1.0 / m
	var llExp float64
	for _, x := range xs {
		if x <= 0 {
			llExp += -30
			continue
		}
		llExp += math.Log(lambda) - lambda*x
	}
	aicExp := 2*1 - 2*llExp // k=1 (lambda)

	// Log-likelihood under normal(mean, stddev)
	if s == 0 {
		return "exponential"
	}
	var llNorm float64
	for _, x := range xs {
		z := (x - m) / s
		llNorm += -math.Log(s) - 0.5*math.Log(2*math.Pi) - 0.5*z*z
	}
	aicNorm := 2*2 - 2*llNorm // k=2 (mean, stddev)

	if aicExp < aicNorm {
		return "exponential"
	}
	return "normal"
}
