# Golang Mutual CloudFoundry
This library provides a http-Client, which uses the [Cloudfoundry Instance Identity Credentials](https://docs.cloudfoundry.org/devguide/deploy-apps/instance-identity.html) for mutual TLS.

## Usage
Like every other `http.Client`
```
mutualClient, err := mutual.GetMutualClient()
if err != nil {
	t.Error(err)
}

res, err := mutualClient.Get(ts.URL)
```