define adapter as a endpoint with zpr.adapter.cn

define ZServicePingable as a service with endpoint.zpr.adapter.cn:'service.zpr.org'

allow zpr.adapter.cn:'client.zpr.org' adapter to access ZServicePingable

allow zpr.adapter.cn:'client.zpr.org' endpoints to access VisaService
