// A synthetic module with deliberate boundary violations, used to prove the
// checker catches one. It is a separate module so the repository's own build
// never links it, and it lives under testdata so the go tool ignores it.
module example.com/fixture

go 1.21
