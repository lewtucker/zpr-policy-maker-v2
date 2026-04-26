# Example user input:

My corporate data center has a large number of users, some of which are employees, others are partners, and maybe other are auditors.  Each user is in one or more defined groups:
    - sales, engineering, marketing, legal, finance: human resources (AKA HR), IT

There may be other attributes for employees such as: employee_id, teams, remote-worker, on-leave, new-hire
  
Access to systems is to be governed by rules based on properties of the users, groups, roles, or possibly the location. For example we may want to allow only members of the HR group to be able to see employee information or access services or databases with this kind of data.

In addition to users, we have lots of resources such as servers which are physical devices in our datacenter. These devices are where services or applications run, and we want to control access to these devices, and services or applications (apps).  We also have networks that can be used to limit who or what can communicate or acess another resource.

Each user, device or system needs to have an unique identity and name.  Other attributes or properties might be the role that the user plays such as employee, partner, customer, or partner.  In general these may be tags either by themselves or setup as key:value pairs such as employee-type:intern.

Some servers, services or devices may have additional attributes at a finer grain level things like IP address or ranges, operating systems, status such as production or development.

Today we have ser
# Rules
Rules always need to include either a Allow or Deny.  The default action for something that doesn't match a rule is to deny it.

Here are a few rules:

Allow sales team to access customer systems and data.
Block interns from accessing development systems.
Allow HR to access employee systems and data.

The output should be conforming to the ZPL spec so that it can be used by a policy enforcement system in the datacenter or other such systems.

