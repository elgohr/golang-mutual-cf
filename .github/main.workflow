workflow "Test" {
  resolves = ["Go Test"]
  on = "push"
}

action "Go Test" {
  uses = "elgohr/asdf-build-action@master"
  env = {
    VERSION = "1.12"
    ENVIRONMENT = "golang"
  }
  args = "go test ./..."
}
