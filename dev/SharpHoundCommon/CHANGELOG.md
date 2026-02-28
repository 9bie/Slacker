# Changelog

## v2.0.13
### Summary
Fix ranged retrieval and allow for changing the LDAP authtype via the ldapconfig

## v2.0.12
### Summary
Readme updates and a null check in gpolocalgroup

## v2.0.11
### Summary
Some updates to try and fix running under netonly context

## v2.0.10
### Summary
Code cleanup and logging

## v2.0.9
### Summary
Adds some new properties to users based on https://github.com/BloodHoundAD/BloodHound/issues/380. Also filters the unactionable local error exceptions

## v2.0.8
### Summary
Removes the ToListAsync call which was failing when compiled through Fody. Adds more logging in various locations

## v2.0.7 (2021DEC16)
### Summary
Add version property to MetaTag

## v2.0.6 (2021DEC15)
### Summary
Add a new helper function for GPOLocalGroups

## v2.0.4 (2021DEC15)
### Summary
Adds GPO local group info to Domain and OU output objects

## v2.0.3 (2021DEC13)
### Summary
Adds a ping cache to the PortScanner

### Adds
* Ping cache for port scanner
* ClearCache function for port scanner
* Add gpoptions to LDAP Properties

## v2.0.2 (2021DEC09)
### Summary
Refactors SPNTargets to include the edge name in the Service instead of a generic indicator. Renamed to SPNPrivilege

## v2.0.1 (2021DEC09)
### Summary
Adds some helper functions for using built in types instead of parsing by hand

## v2.0.0 (2021DEC09)
### Summary
Major overhaul for logging in the project. Removes async annotations for several functions that were running synchronously. Code cleanup.

### Adds
* Better logging across almost all components of the library. 
* Logging will now prefix classes that the logs are generated from for tracing
* Many LDAP Properties have been extracted into constants to prevent spelling errors
* More function comments

### Fixes
* Remove an internal DCOnly flag, replace in context
* Fixes ranged retrieval not working correctly
* Remove async from ResolveAccountName
* Remove async from GetBaseEnterpriseDC
* Remove async from GetSidFromDomainName

## v1.1.3 (2021DEC1)
### Summary
Adds the IsMSA and IsGMSA functions to search result entries

## v1.1.2 (2021NOV17)
### Summary
Adds the TestLDAPConfig function to LDAPUtils

## v1.1.1 (2021NOV17)
### Summary
Split privileged and unprivileged session enumeration. Add registry session enumeration. Expose some new functions and more prep for the new FOSS SharpHound

### Added
* Added the GetDomain function
* Added the ReadUserSessionsRegistry function
* Added an overload for ComputerAvailability allowing an override for portscan timeout

### Fixes
* Add missing computer datatype in consts
* Fixes resolution of GMSA accounts to user accounts earlier in resolution

## v1.1.0 (2021OCT14)
### Summary
Completely remove the Newtonsoft.JSON dependency. Prepare some components for FOSS SharpHound rewrite

### Fixes
* Add StatusNoSuchAlias to NTSTATUS
* Add a null check to property processors
* Fix some visibility issues for functions/classes

## v1.0.16 (2021SEP22)
### Summary
Bugfixes and code cleanup

### Fixes
* Properly dispose OBJECT_ATTRIBUTES  in SamRPCServer
* Add a finalizer to SamRPCServer
* Add the PDB file for the common library to the nuget package
* Fix a nullpointerexception in ldap query exception handling

## v1.0.15 (2021AUG17)
### Summary
Allow AddFilter to be optional instead of mandatory AND

## v1.0.14 (2021AUG17)
### Summary
Bugfixes and two new edges

### Adds
* Adds the WriteSPN edge
* Adds the AddKeyCredentialLink edge

### Fixes
* Fix LDAP filter incorrectly using OR instead of AND
* Fix an incorrect edge GUID in ACE processing


## v1.0.13 (2021AUG09)
### Summary
Bugfixes and debugging fixes

### Fixes
* Filter blank/null domains from NetWkstaUserEnum
* Fix unresolved domains in Well Known Principals

## v1.0.12 (2021JUL29)

### Summary
Populate the Enterprise Domain Controllers group properly

## v1.0.11 (2021JUL29)

### Summary
Adds new properties to well known principals, avoid returning null in most places.

### Adds
* Add 'domainsid' property to well known principals
* Add 'domain' property to well known principals
* Add a function to return all seen well known principals for the current run
* Some more logging updates

### Fixes
* Fixes some incorrectly named well known principals
* Add some guards against null object identifiers 

## v1.0.10 (2021JUL19)

### Summary
Fixes a consistency issue between OUs and Domain objects

## v1.0.9 (2021JUL15)

### Summary
More tests and a ton of code cleanup

### Fixes
* Force distinguished names coming back from group membership to upcase

## v1.0.8 (2021JUN30)

### Summary
More tests.

### Added
* Add the 'whenCreated' attribute to property collections

### Fixes
* Fix an error condition in ConvertTimestampToUnixEpoch


## v1.0.7 (2021JUN23)

### Summary
Add docfx action to github. Lots of refactoring of classes for testability, and lots more tests.

## v1.0.6 (2021JUN09)

### Summary

New project structure, addition of documentation and testing tool integration. Add several unit tests, and start making stuff non-static. 

Fixes a bug in ACL processing that was resulting in duplicate items

### Added

* README.md
* CHANGELOG.md
* QUICKSTART.md
* tools/
* tools/scripts
* tools/scripts/app-build.ps1
* tools/scripts/app-test.ps1
* tools/scripts/app-publish.ps1
* tools/scripts/doc-build.ps1
* tools/scripts/doc-serve.ps1
* tools/scripts/doc-publish.ps1
* src/
* test/
* test/unit
* docfx/
* docs/

### Changed

* Moved `CommonLib` into `/src` folder


## v1.0.5 (2021JUN03)

### Summary
Add a bunch more logging, fix a missed memory free in the implementation of local group enumeration

## v1.0.4 (2021JUN02)

### Summary
Change the Unknown label to Base, remove dependencies on SearchResultEntries from all functions so they're consumable by anything

### Fixed
* Cache will now create missing items
* Fixed an accidental double add to the properties array
* Fix visibility of functions
* Fix a crash in session enumeration caused by marshalling incorrectly
* Fix well known sid resolution causing a Null Pointer Exception

## v1.0.3 (2021MAY21)

## Summary
Fixes some bugs in LDAP query logging, as well as cache serialization.

## v1.0.2 (2021MAY18)

### Summary
First official publish to Nuget and project setup
