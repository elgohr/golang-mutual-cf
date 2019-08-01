workflow "Test" {
  resolves = ["Go Test"]
  on = "push"
}

action "Go Test" {
  uses = "elgohr/asdf-build-action@master"
  env = {
    VERSION = "1.13"
    LANGUAGE = "go"
  }
  args = "go test ./..."
}
