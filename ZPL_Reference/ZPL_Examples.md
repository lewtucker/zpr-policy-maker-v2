# ZPL Examples
# Source: ZPR RFC-15.5 (Applied Invention, LLC, September 2025)


## Class Definitions (Define statements)

# Basic user subclass with required attributes and optional tags
Define employee as a user with an ID-number, roles and optional tags full-time, part-time,
    and intern.

# Service with a single-valued attribute
Define gateway as a service with an external-network-connection.

# Subclass with a fixed attribute value (restricts inherited attribute)
Define internet-gateway as a gateway with external-network-connection:public-internet.

# AKA clause — defines a non-standard plural synonym
Define mouse AKA mice as peripheral with function:pointing.


## Allow Statements (Permissions)

# User class accessing a service class — no endpoint restriction
Allow sales employees to access customer databases.

# User class on a specific endpoint type accessing a service class
# "on" before the verb = attribute of the accessor's endpoint
Allow sales employees on managed laptops to access customer databases.

# "on" after the service = attribute of the endpoint hosting the service
Allow sales employees to access customer databases on sales endpoints.

# Attribute-value filter on subject (department:sales instead of a tag)
Allow department:sales employees on managed laptops to access customer databases.

# Named service instance (proper name, capitalized by convention)
Allow HR employees to access Timesheet-database.

# Load-balancer pattern: two rules required for end-to-end access
Allow cleared government users to access Timesheet-load-balancer.
Allow Timesheet-load-balancer to access Timesheet-database.


## Never Statements (Denials)

# Deny by class
Never allow internet-gateways to access internal services.

# Deny by attribute value
Never allow role:intern users to access classified services.


## Circumstance-Conditioned Statements (§4.4 — syntax not yet fully defined)

# Time-of-day condition
Never allow backup:nightly servers to access backup-services before 18:00 GMT.

# Data-volume limit
Allow Service2 access to Service1, limited to 10Gb/day.


## Signaling Statements (§4.5)

# Signal an event to a named logging service whenever this permission fires
Allow top-secret users to access top-secret services and signal "accessing" to Access-logger.
