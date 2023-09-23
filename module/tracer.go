package module

import (
	"context"
	"gosolo/module/trace"

	otelTrace "go.opentelemetry.io/otel/trace"
)

var (
	_ Tracer = &trace.Tracer{}
	_ Tracer = &trace.NoopTracer{}
)

// Tracer interface for tracers in flow. Uses open tracing span definitions
type Tracer interface {
	ReadyDoneAware

	StartSpanFromContext(
		ctx context.Context,
		operationName trace.SpanName,
		opts ...otelTrace.SpanStartOption,
	) (
		otelTrace.Span,
		context.Context,
	)

	StartSpanFromParent(
		parentSpan otelTrace.Span,
		operationName trace.SpanName,
		opts ...otelTrace.SpanStartOption,
	) otelTrace.Span

	// WithSpanFromContext encapsulates executing a function within an span, i.e., it starts a span with the specified SpanName from the context,
	// executes the function f, and finishes the span once the function returns.
	WithSpanFromContext(
		ctx context.Context,
		operationName trace.SpanName,
		f func(),
		opts ...otelTrace.SpanStartOption,
	)
}
