# Golang Mutual CloudFoundry
[![Actions Status](https://wdp9fww0r9.execute-api.us-west-2.amazonaws.com/production/badge/elgohr/golang-mutual-cf)](https://wdp9fww0r9.execute-api.us-west-2.amazonaws.com/production/results/elgohr/golang-mutual-cf)

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
