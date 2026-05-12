## ZPL Rules for Lab automation, opentrons

# Lab setup
We are a small laboratory testing company.  We use Opentrons Equipment and controllers for running tests driven by  AI agents such as openclaw. We view agents as users which have an identity, and status such as in-service, out-of-service, rogue.  We run a set of automated services running on expensive workstations and other robots for doing things such handling reagents, drying samples, and performing experiments.   It's important that only authorized operators and agents access certain workstations.  We also have technicians such a Bob and Joe who perform monthly maintenance. Bigboy is the name of one of our agents that can access all workstations for maintenance.






Define LabAgent as a service with role:automation-agent.
Define AuthorizedOperator as a service with role:operator, authorization:run-approved.
Define opentrons as a service with multiple endpoint and multiple method.
Define LabTech as a user with role:technician and optional tags part-time, full-time.

Never allow LabAgent to access opentrons with method:DELETE
Never allow LabAgent to access opentrons with endpoint:robot-234
Allow AuthorizedOperator to access opentrons with endpoint:repair
Allow LabAgent to access opentrons with endpoint:analyze

