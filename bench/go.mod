module github.com/ergasterion-dev/aegolith/bench

go 1.25

replace github.com/ergasterion-dev/aegolith => ../

require (
	github.com/ergasterion-dev/aegolith v0.0.0-00010101000000-000000000000
	gopkg.in/yaml.v3 v3.0.1
)

require github.com/corazawaf/libinjection-go v0.3.7 // indirect
