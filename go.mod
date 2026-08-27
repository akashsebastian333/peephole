module peephole

go 1.26

// Pinned so a local ./build.sh produces the same artifact CI publishes.
// go1.26.0 was reachable-affected by GO-2026-4602 (fixed in go1.26.1).
// Bump deliberately, together with .github/workflows/release.yml.
toolchain go1.26.6
