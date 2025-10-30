package analytics

import (
	"strconv"
	"time"

	"github.com/August26/proxycheck-go/internal/model"
)

func Compute(results []model.ProxyCheckResult, totalDuration time.Duration) model.BatchStats {
    var (
        total       = len(results)
        uniqueSet   = map[string]struct{}{}
        alive       = 0
        totalLatencyMs int64
        latencyCount   int64
        fraudSum    int64
        fraudCount  int64
    )

    for _, r := range results {
        uniqueSet[r.Input.Host+":"+strconv.Itoa(r.Input.Port)] = struct{}{}

        if r.Alive {
            alive++
        }

        if r.LatencyMs > 0 {
            totalLatencyMs += int64(r.LatencyMs)
            latencyCount++
        }

        if r.FraudScore > 0 {
            fraudSum += int64(r.FraudScore)
            fraudCount++
        }
    }

    avgLatency := 0.0
    if latencyCount > 0 {
        avgLatency = float64(totalLatencyMs) / float64(latencyCount)
    }

    avgFraud := 0.0
    if fraudCount > 0 {
        avgFraud = float64(fraudSum) / float64(fraudCount)
    }

    successRate := 0.0
    if total > 0 {
        successRate = (float64(alive) / float64(total)) * 100.0
    }

    return model.BatchStats{
        TotalProxies:          total,
        UniqueProxies:         len(uniqueSet),
        AliveProxies:          alive,
        SuccessRatePct:        successRate,
        AvgLatencyMs:          avgLatency,
        AvgFraudScore:         avgFraud,
        TotalProcessingTimeMs: totalDuration.Milliseconds(),
    }
}

func Compute(results []model.ProxyCheckResult, duration time.Duration) model.BatchStats {
	stats := model.BatchStats{
		TotalProxies:          len(results),
		TotalProcessingTimeMs: duration.Milliseconds(),
	}

	seen := make(map[string]struct{})

	var aliveCount int
	var latencySum int64
	var latencyCount int64

	var fraudSum float64
	var fraudCount int64

	for _, r := range results {
		key := r.Input.Host + ":" + strconv.Itoa(r.Input.Port)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
		}

		if r.Alive {
			aliveCount++
			if r.LatencyMs > 0 {
				latencySum += r.LatencyMs
				latencyCount++
			}
			if r.FraudScore > 0 {
				fraudSum += r.FraudScore
				fraudCount++
			}
		}
	}

	stats.UniqueProxies = len(seen)
	stats.AliveProxies = aliveCount

	if latencyCount > 0 {
		stats.AvgLatencyMs = float64(latencySum) / float64(latencyCount)
	}
	if fraudCount > 0 {
		stats.AvgFraudScore = fraudSum / float64(fraudCount)
	}

	return stats
}
