# Example user input:

My corporate data center has a large number of users, some of which are employees, others are partners, and maybe other are auditors.  Each user is in one or more defined departments:
    - corp, sales, engineering, finance, hr (human resources, recruiting), admin

There may be other attributes for employees such as: employee_id, teams, remote-worker, on-leave, new-hire
  
Access to systems is to be governed by rules based on properties of the users, groups, roles, or possibly the location. For example we may want to allow only members of the HR group to be able to see employee information or access services or databases with this kind of data.

In addition to users, we have lots of resources such as servers which are physical devices or endpoints in our datacenter. These devices are where services or applications run, and we want to control access to these devices, and services or applications (apps).  

Each user, device or system needs to have an unique identity and name.  Other attributes or properties might be the role that the user plays such as employee, partner, customer, or partner.  In general these may be tags either by themselves or setup as key:value pairs such as employee-type:intern.

Some servers, services or devices may have additional attributes at a finer grain level things like IP address or ranges, operating systems, status such as production or development.

Here are a few rules:

Allow sales team to access customer systems and data.
Block interns from accessing development systems.
Allow HR to access employee systems and data.

The output should be conforming to the ZPL spec so that it can be used by a policy enforcement system in the datacenter or other such systems.

