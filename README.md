# Golang Mutual CloudFoundry
[![Actions Status](https://github.com/elgohr/golang-mutual-cf/workflows/Test/badge.svg)](https://github.com/elgohr/golang-mutual-cf/actions)

This library provides a http-Client, which uses the [Cloudfoundry Instance Identity Credentials](https://docs.cloudfoundry.org/devguide/deploy-apps/instance-identity.html) for mutual TLS.

## Usage
Like every other `http.Client`

```
client, err := mutual.GetClient()
if err != nil {
	t.Error(err)
}

res, err := client.Get(ts.URL)
```
