# Golang Mutual CloudFoundry
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

Please note that certificates are expiring in intervals around an hour.  
They will not be updated. In this case a new client must be retrieved.