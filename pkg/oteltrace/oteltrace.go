// Package oteltrace centralizes OpenTelemetry tracing setup for every
// platform process (API and workers). Configuration is environment-driven
// and optional: without an observability backend the package stays a no-op
// and processes behave exactly as before.
//
// Environment variables (OpenTelemetry standard conventions):
//
//	OTEL_SERVICE_NAME            service name override (default per process)
//	OTEL_EXPORTER_OTLP_ENDPOINT  OTLP base URL, e.g. http://localhost:4317
//	OTEL_EXPORTER_OTLP_PROTOCOL  grpc | http/protobuf (default http/protobuf)
//	OTEL_TRACES_EXPORTER         otlp (default) | stdout | none
//
// Tracing activates when an OTLP endpoint is configured or
// OTEL_TRACES_EXPORTER=stdout (debug: spans printed to the process log).
// Sampling is always-on: traces may assist future audit-style queries, so
// spans are kept until a backend imposes its own retention.
package oteltrace

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

var enabled bool

// Enabled reports whether Setup activated tracing. Handlers use it to mount
// middleware only when a backend is configured.
func Enabled() bool { return enabled }

// Setup installs the global tracer provider when tracing is enabled and
// returns a shutdown function that flushes pending spans. When tracing is
// disabled Setup is a no-op and all spans created through the global
// providers remain no-ops.
func Setup(ctx context.Context, defaultServiceName string) (func(context.Context) error, error) {
	noOp := func(context.Context) error { return nil }

	exporterKind := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_EXPORTER")))
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if exporterKind == "" {
		exporterKind = "otlp"
	}
	if exporterKind == "none" {
		return noOp, nil
	}
	if exporterKind != "stdout" && endpoint == "" {
		// No backend configured: keep the process in its previous no-op state.
		return noOp, nil
	}

	serviceName := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME"))
	if serviceName == "" {
		serviceName = defaultServiceName
	}

	var (
		exporter sdktrace.SpanExporter
		err      error
		batched  bool
	)
	switch exporterKind {
	case "stdout":
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
		batched = false // print spans immediately so short-lived debug runs show them
	case "otlp":
		protocol := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")))
		if protocol == "" {
			protocol = "http/protobuf"
		}
		if protocol == "grpc" {
			exporter, err = otlptracegrpc.New(ctx, otlptracegrpc.WithEndpointURL(endpoint))
		} else {
			exporter, err = otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(endpoint))
		}
		batched = true
	default:
		return noOp, fmt.Errorf("unsupported OTEL_TRACES_EXPORTER %q", exporterKind)
	}
	if err != nil {
		return noOp, fmt.Errorf("create trace exporter: %w", err)
	}

	res, err := resource.Merge(resource.Default(),
		resource.NewSchemaless(attribute.String("service.name", serviceName)))
	if err != nil {
		return noOp, fmt.Errorf("merge trace resource: %w", err)
	}

	samplerOptions := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
	}
	if batched {
		samplerOptions = append(samplerOptions, sdktrace.WithBatcher(exporter))
	} else {
		samplerOptions = append(samplerOptions, sdktrace.WithSyncer(exporter))
	}
	provider := sdktrace.NewTracerProvider(samplerOptions...)

	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))
	enabled = true
	return provider.Shutdown, nil
}

// TraceParentFromContext returns the W3C traceparent header value for the
// active span in ctx, or "" when there is none. Queue payloads embed it to
// keep traces continuous across asynq, which has no task headers.
// It always returns "" while tracing is disabled.
func TraceParentFromContext(ctx context.Context) string {
	if !trace.SpanContextFromContext(ctx).IsValid() {
		return ""
	}
	carrier := propagation.MapCarrier{}
	propagation.TraceContext{}.Inject(ctx, carrier)
	return carrier.Get("traceparent")
}

// ContextWithTraceParent attaches traceParent (W3C traceparent) to ctx as a
// remote parent span. Empty or invalid values leave ctx unchanged.
func ContextWithTraceParent(ctx context.Context, traceParent string) context.Context {
	traceParent = strings.TrimSpace(traceParent)
	if traceParent == "" {
		return ctx
	}
	extracted := propagation.TraceContext{}.Extract(ctx, propagation.MapCarrier{"traceparent": traceParent})
	if !trace.SpanContextFromContext(extracted).IsValid() {
		return ctx
	}
	return extracted
}
