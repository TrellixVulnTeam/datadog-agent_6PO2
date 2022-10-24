// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package sampler

import (
	"math/rand"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/pkg/trace/config"
	"github.com/DataDog/datadog-agent/pkg/trace/pb"
	"github.com/stretchr/testify/assert"
)

func randomTraceID() uint64 {
	return uint64(rand.Int63())
}

func getTestPrioritySampler() *PrioritySampler {
	// No extra fixed sampling, no maximum TPS
	conf := &config.AgentConfig{
		ExtraSampleRate: 1.0,
		TargetTPS:       0.0,
	}

	return NewPrioritySampler(conf, &DynamicConfig{})
}

func getTestTraceWithService(service string, s *PrioritySampler) (*pb.TraceChunk, *pb.Span) {
	tID := randomTraceID()
	spans := []*pb.Span{
		{TraceID: tID, SpanID: 1, ParentID: 0, Start: 42, Duration: 1000000, Service: service, Type: "web", Meta: map[string]string{"env": defaultEnv}, Metrics: map[string]float64{}},
		{TraceID: tID, SpanID: 2, ParentID: 1, Start: 100, Duration: 200000, Service: service, Type: "sql"},
	}
	priority := PriorityAutoDrop
	r := rand.Float64()
	rates := s.rateByService.rates
	key := ServiceSignature{spans[0].Service, defaultEnv}

	serviceRate, ok := rates[key.String()]
	if !ok {
		serviceRate, _ = rates[ServiceSignature{}.String()]
	}
	rate := float64(1)
	if serviceRate != nil {
		rate = serviceRate.r
	}
	if r <= rate {
		priority = PriorityAutoKeep
	}
	spans[0].Metrics[agentRateKey] = rate
	return &pb.TraceChunk{
		Priority: int32(priority),
		Spans:    spans,
	}, spans[0]
}

func TestPrioritySample(t *testing.T) {
	// Simple sample unit test
	assert := assert.New(t)

	env := defaultEnv

	s := getTestPrioritySampler()

	assert.Equal(float32(0), s.sampler.totalSeen, "checking fresh backend total score is 0")
	assert.Equal(int64(0), s.sampler.totalKept.Load(), "checking fresh backend sampled score is 0")

	s = getTestPrioritySampler()
	chunk, root := getTestTraceWithService("my-service", s)

	chunk.Priority = -1
	sampled := s.Sample(time.Now(), chunk, root, env, 0)
	assert.False(sampled, "trace with negative priority is dropped")
	assert.Equal(float32(0), s.sampler.totalSeen, "sampling a priority -1 trace should *NOT* impact sampler backend")
	assert.Equal(int64(0), s.sampler.totalKept.Load(), "sampling a priority -1 trace should *NOT* impact sampler backend")

	s = getTestPrioritySampler()
	chunk, root = getTestTraceWithService("my-service", s)

	chunk.Priority = 0
	sampled = s.Sample(time.Now(), chunk, root, env, 0)
	assert.False(sampled, "trace with priority 0 is dropped")
	assert.True(float32(0) < s.sampler.totalSeen, "sampling a priority 0 trace should increase total score")
	assert.Equal(int64(0), s.sampler.totalKept.Load(), "sampling a priority 0 trace should *NOT* increase sampled score")

	s = getTestPrioritySampler()
	chunk, root = getTestTraceWithService("my-service", s)

	chunk.Priority = 1
	sampled = s.Sample(time.Now(), chunk, root, env, 0)
	assert.True(sampled, "trace with priority 1 is kept")
	assert.True(float32(0) < s.sampler.totalSeen, "sampling a priority 0 trace should increase total score")
	assert.True(int64(0) < s.sampler.totalKept.Load(), "sampling a priority 0 trace should increase sampled score")

	s = getTestPrioritySampler()
	chunk, root = getTestTraceWithService("my-service", s)

	chunk.Priority = 2
	sampled = s.Sample(time.Now(), chunk, root, env, 0)
	assert.True(sampled, "trace with priority 2 is kept")
	assert.Equal(float32(0), s.sampler.totalSeen, "sampling a priority 2 trace should *NOT* increase total score")
	assert.Equal(int64(0), s.sampler.totalKept.Load(), "sampling a priority 2 trace should *NOT* increase sampled score")

	s = getTestPrioritySampler()
	chunk, root = getTestTraceWithService("my-service", s)

	chunk.Priority = int32(PriorityUserKeep)
	sampled = s.Sample(time.Now(), chunk, root, env, 0)
	assert.True(sampled, "trace with high priority is kept")
	assert.Equal(float32(0), s.sampler.totalSeen, "sampling a high priority trace should *NOT* increase total score")
	assert.Equal(int64(0), s.sampler.totalKept.Load(), "sampling a high priority trace should *NOT* increase sampled score")

	chunk.Priority = int32(PriorityNone)
	sampled = s.Sample(time.Now(), chunk, root, env, 0)
	assert.False(sampled, "this should not happen but a trace without priority sampling set should be dropped")
}
