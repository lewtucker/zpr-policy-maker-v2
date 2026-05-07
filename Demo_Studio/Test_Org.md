# Acme Corporation — ZPL Policy Design

## Overview. - this verions doesn't say anything about namespaces

## Prompt: Guidence for making ZPL rules

Acme Corporation operates a large enterprise datacenter serving employees across six departments: HR, Finance, Engineering, Legal, Sales, and Administration. Users range from full-time employees and managers to executives (CEO, SVP, EVP), interns, external partners, and auditors. Resources and services include sensitive databases (payroll, employee records, revenue tracking), legal archives (patent library), customer-facing systems, and engineering development infrastructure. These services should only be accessible to employees in the corresponding department or the senior executives.  Servers running these apps are endpoints with a classification level of:  `confidential` for legal and financial, `corporate` for general employees, and 'development' for engineering and administration.   Map the services, such as databases, to run on appropriately named servers as endpoints, so there are simple ways to restrict access.

When making rules, after defining the users, services, and endpoints it's advisable to start with a service designed for a particular department, for example a legal database should only allow access for those in the legal department, visitors may only have access to an employee register to look up employees.

A hint on the use of Never Allow rules.  In general things are easier when only Allow rules are made, but when it's necessary to block only some employees from something broadly accessed, two rules can be used.  For example, if we wanted to give all employees access to benefits except those in the state of Tennessee, we could do that as follows:

- Allow employees with employee_id: to access benefits
- Never allow employees with state:Tennessee to access benefits

This lets only employees with an employee_id access benefits while narrowly blocking those employees that either lack a employee_id or are in the state of Tennessee.

Try to make this based on a realistic scenario of what might go on in a corporation or business.
