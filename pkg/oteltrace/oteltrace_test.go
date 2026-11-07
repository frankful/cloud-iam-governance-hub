package oteltrace

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// useTestProvider installs a real SDK provider so contexts carry valid span
// contexts, and restores the previous provider afterwards.
func useTestProvider(t *testing.T) {
	t.Helper()
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample())))
	t.Cleanup(func() { otel.SetTracerProvider(previous) })
}

func TestTraceParentRoundTrip(t *testing.T) {
	useTestProvider(t)

	if got := TraceParentFromContext(context.Background()); got != "" {
		t.Fatalf("TraceParentFromContext(background) = %q, want empty", got)
	}

	ctx, span := otel.Tracer("test").Start(context.Background(), "producer")
	defer span.End()

	traceParent := TraceParentFromContext(ctx)
	if !strings.HasPrefix(traceParent, "00-") || len(traceParent) < 55 {
		t.Fatalf("traceparent = %q, want W3C header", traceParent)
	}

	consumer := ContextWithTraceParent(context.Background(), traceParent)
	producerSC := trace.SpanContextFromContext(ctx)
	consumerSC := trace.SpanContextFromContext(consumer)
	if consumerSC.TraceID() != producerSC.TraceID() {
		t.Fatalf("trace id = %s, want %s", consumerSC.TraceID(), producerSC.TraceID())
	}
	if !consumerSC.IsRemote() {
		t.Fatal("extracted span context must be remote")
	}
	// The remote context points at the producer span as its parent link.
	if consumerSC.SpanID() != producerSC.SpanID() {
		t.Fatalf("parent span id = %s, want producer span %s", consumerSC.SpanID(), producerSC.SpanID())
	}
	// A child started from it must get a fresh span id, not reuse the parent's.
	_, child := otel.Tracer("test").Start(consumer, "consumer")
	childSC := child.SpanContext()
	child.End()
	if childSC.SpanID() == producerSC.SpanID() {
		t.Fatal("child span must not reuse the parent span id")
	}
	if childSC.TraceID() != producerSC.TraceID() {
		t.Fatalf("child trace id = %s, want %s", childSC.TraceID(), producerSC.TraceID())
	}
}

func TestContextWithTraceParentInvalidValues(t *testing.T) {
	base := context.Background()
	for _, value := range []string{"", "   ", "garbage", "00-00000000000000000000000000000000-0000000000000000-01"} {
		got := ContextWithTraceParent(base, value)
		if got != base {
			t.Errorf("ContextWithTraceParent(%q) modified context", value)
		}
	}
}

func TestEnqueueTraceparentAbsentWithoutSpanContext(t *testing.T) {
	// Without any active span the helper must stay silent so payloads remain
	// small and stable while tracing is disabled.
	if got := TraceParentFromContext(context.Background()); got != "" {
		t.Fatalf("traceparent = %q, want empty without span context", got)
	}
}
