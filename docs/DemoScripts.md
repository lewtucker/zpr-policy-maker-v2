## DemoScripts

Here are some notes regarding running different kinds of demos of the ZPR-Policy-Maker

# 1. Filename conventions

**Pathname: /demo**.  extensions ZPL = *.txt,  yaml = *.yaml
Demos are stored under different user names, e.g. zpl, rfc, oci, etc.  and the password is the username followed by 12345, eg. rfc12345
If changes are made to the demo accounts, these should be deleted or the account may have to be deleted by the admin and recreated.

The Example ZPL is what is loaded by default

| Demo Type | username | Classes |Entities| Rules|
|---|---|---|---|---|
| ZPR RFC-15.5| rfc | RFC_classes | RFC_Entities| RFC_Rules|
| Example ZPL | zpl | ZPL_classes| ZPL_entities| ZPL_rules|
| OCI w/o namespace | oci | oci_classes| oci_entities| oci_rules|
| OCI w/ namespace| oci_ns| oci_ns_classes| oci_ns_classes| oci_ns_rules|
| Corporation | corp | corp_classes | corp_entities | corps_rules |


# DEMO SCRIPT

To run a demo, decide what to use:  RFC-15.5 examples,  Corporation example, or OCI

These should all be ready with preloaded classes, entities, and rules.  It no, delete and reload from disk.

First go to Getting Started to explain the system.  All based on RFC-15.5, it can understand ZPL language, and had taken examples from the RFC to build a vocabulary, BNF parser, etc.

The system is designed to be integrated into a real-time system which outputs actions to the system which responds with either Accept or Never.

Let's first look at the Classes, Entities and Rules.  Note you can create your own classes, entities and rules. Typically, entities would come from a trusted source such as LDAP or Active Directory.  Here are just preload several examples of employees, service, and other resources.

Let's look at the ZPL Rules.  Several have been preloaded here for a corporation.  Click on the Rule: Finance access HR Databases.  Clock on the checkbox.  Evaluate it.  Now change finance to Legal. Evaluate it and it is denied.  Show the traces and you'll see what rules didn't apply until it found no rule matched so it was rejected.

While these rules were made by hand to meet the situation, we can also add our own individual rules or look at the rules as they appear in ZPL.  Now lets add a new rule. We can do this in a structured way, (Press NEW Rule) or write the rule in ZPL through Import ZPL text, such as:

'''Allow department:sales employee to access services:customer servers'''

Alternatively we can get help from AI to create ZPL structured rules from natural english:

AI Rule Assistant:  Say, '''I want Developers to be able to access development servers'''.   Look at the YAML, accept and test and we can see that it matches.

Going even further, given the vocabulary, we can ask another AI to make up a certain number of Accept or Never rules for us automatically.  Each one we can test and accept or discard.

Scenario testing works in a similar way, but is still in development. It's meant to create rules for meet a broader set of concerns.

Laslty this is really meant to be a policy enforcement service for an external system. It has ZPI endpoints (see ./docs) which other services can send in requests and get back either Accept or Deny.  Here we have our own test generator service that creates a set of test cases to send to our own endpoint.  Demo Test Runner.  Take a look at the Activity log and you can see that the test runner injected each of these rules and gave back verdicts.

You can each try this yourself.  Goto zpr-policy.lewtucker.net.  Make up a user name, use the password ZPR and it will setup an account for you.  You can change your password to something better to protect your account, and make up or test your own rules. You can't hurt the system, so you can delete all but the ZPL system classes and rules. This system is in development so I can't guarantee to preserve your data, but give it a try.