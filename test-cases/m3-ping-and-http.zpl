define adapter as a endpoint with zpr.adapter.cn
define GoldenClient as an adapter with zpr.adapter.cn:'client.zpr.org'

define ZServicePingable as a service with endpoint.zpr.adapter.cn:'service.zpr.org'
define ZWebService as a service with endpoint.zpr.adapter.cn:'service.zpr.org'

allow GoldenClient to access ZServicePingable
allow GoldenClient to access ZWebService

allow zpr.adapter.cn:'client.zpr.org' endpoints to access VisaService
