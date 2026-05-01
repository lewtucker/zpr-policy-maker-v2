# New Direction for ZPL Policy Maker V3

I want to change the workflow.  Can create a new UI for ZPR-Policy-Maker-3.  The approach here is going to be diferent. 

# Namespaces

We need a superior root level Class called Namespace, from which other subclasses can be created:  User, Service, Endpoint, and Namespace  Each namespace will have an owner attribute and only the owner of the namespace can add new definitions and rules.   Delegation happens when a new namespace object is created by the current owner, naming another user as the owner.

 First of all, we want this to be ZPL centric.  In the UI We need the concept of the logged in, current user.  Each user will be able to create a namespace, within which the user creates ZPL definitions and rules.  In the backgrounnd, the system will create the necessary classes, objects, etc. which the user can chose to see through a pull down menu.  The user should first create a new namespace, which is visibly shown on each page.  Next the user should write ZPL to define a service and additional ZPL definitions for attributes or tags, and also rules in ZPL pertaining to that service.  All of this is within the current namespace.  The owner of the current namespace is the current user.   The owner can create other users and namespaces via ZPL statements. The UI should allow the current user to "login" as one of the other users.     

 # New UI. (at a new port)

 Start with the basics described above.  Show me a mock up and we will iterate from there. 

 Can we make such a new frontend without destroying the current UI?
    

