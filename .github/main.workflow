workflow "Test" {
  resolves = ["Go Test"]
  on = "push"
}

action "Go Test" {
  uses = "elgohr/asdf-build-action@master"
  env = {
    LANGUAGE = "go"
    VERSION = "1.12"
  }
  args = "go test ./..."
}
