module peephole

go 1.26

// Pinned so a local ./build.sh produces the same artifact CI publishes, and so a
// stale toolchain cannot silently ship known stdlib CVEs. govulncheck found 32
// reachable stdlib vulnerabilities in binaries built with go1.26.0; all are fixed
// in go1.26.6. Bump deliberately, together with .github/workflows/release.yml.
toolchain go1.26.6
