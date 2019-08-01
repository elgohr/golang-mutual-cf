workflow "New workflow" {
  on = "push"
  resolves = ["Go Test"]
}

action "Go Test" {
  uses = "elgohr/asdf-build-action@master"
  env = {
    LANGUAGE = "golang"
    VERSION = "1.13"
  }
  args = "go test ./..."
}
