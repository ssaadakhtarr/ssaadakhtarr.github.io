# Active Directory - An Overview!


<!--more-->

When we talk about Active Directory it's a huge topic that can be discussed in depth and detail. In this post I'll be discussing some of the core and basic concepts related to Active Directory. So without further ado let's get started.

## What is Active Directory?

Active Directory or AD is a directory service developed and provided by Microsoft to manage windows domain networks. A directory service is nothing but a hierarchical structure that stores information about objects such as computers, users, printers etc. on the network. We'll discuss objects in more detail later on. Active Directory runs on Microsoft Windows Server. It provides authentication on Windows based devices using Kerberos and uses RADIUS or LDAP to authenticate non-windows devices such as Linux, firewalls etc.

## So why Active Directory?

Nowadays, Active Directory is the most commonly used identity management service in the world. It makes life easier for administrators and end users while also improving security for businesses. Administrators can centrally manage user & rights and centrally control computer and user configurations. Active Directory keeps track of domain members, such as devices and users, verifies their credentials, and establishes their access privileges.

<br>

<center>
<img src="1.gif" alt="nice" width="400"/>
</center>

## Active Directory Domain Services

Remember the authentication part I talked about earlier? The primary mechanism for authenticating users and identifying which network resources they can access is through Active Directory Domain Services (AD DS), which is a basic component of Active Directory. Single Sign-On (SSO), security certificates, LDAP, and access rights management are all provided by AD DS. AD DS also allows administrators to manage and store information about network resources as well as application data in a distributed database.

## Structure of Active Directory

You can think of Active Directory as a forest. A real world forest has multiple trees and those trees have multiple branches and leaves. In Active Directory, you may think of forest as an organization. So in an Active Directory there can be one or more forests representing an organization and its subsidiaries. Now each forest has one or more trees which we call domains in Active Directory and each tree has various leaves which we call objects in AD. These objects are categorized into Organization Units (OUs) and groups which you can think of as branches of a tree.

<br>

<center>
<img src="2.gif" alt="forest" width="400"/>
</center>

## Components of Active Directory

Active Directory or AD, enables for the hierarchical storing of resources. When adopting AD, there are two components to consider in terms of its structure i.e. Logical and Physical components.

### Logical Components
Logical Components in Active Directory allow you to organize resources in the directory so that their layout mirrors your organization’s logical structure. The logical side is set up in such a way that the hierarchy permits some resources to be placed into other resources, creating a parent-child relationship between them. This connection can be used to quickly manage access rights and permissions.

##### AD DS Schema:
It is a kind of rule book that defines the types of objects that can be stored in the AD. Every object class that can be generated in an Active Directory has a formal definition in the Active Directory schema. The schema also has details about every attribute that can exist in an Active Directory object.

##### Domains:
In an Active Directory context, a domain is a collection of objects. For security and administrative purposes, all objects inside a domain adhere to the same policies. Users attempting to access domain resources must first be authenticated by a server known as a Domain Controller (DC).

##### Trees:
A tree is basically one or more domains grouped together. All domains in a tree share a common namespace. For example, app.example.com and dev.example.com would be considered a part of the example.com domain tree. All the domains in a tree have a trust relationship with other domains.

##### Forest:
A forest is simply a group of one or more trees. Forests share a common schema, domain configurations, application information etc. Forests enable trust between all the domains present in the forest.

##### Organizational Units (OUs):
These are just containers that can contain users, groups, computers, file shares, printers and also other OUs. They can be used to manage a group of objects in a uniform manner, delegate permissions to an administrator group of objects, and apply various policies.

##### Trusts:
It provides a mechanism for users within a domain to access resources in another domain. We have Directional Trust and Transitive Trust. **Directive Trust** is when the direction of trust flows from the trusting domain to the trusted domain. While in an Active Directory forest, **Transitive Trust** is a two-way connection that is automatically generated between parent and child domains. By default, when a new domain is created, it shares resources with its parent domain, allowing an authenticated user to access resources in both domains. In transitive trust you can also say that one domain trusts another domain but in this case it also trusts everything that the other domain trusts as well.

### Physical Components
This refers to where hardware, such as servers, are physically located in the physical world. To maintain performance efficiency between servers and resources, it is critical to properly design the physical structure. 
With the separation of logical and physical components, users are able to find resources more easily and administrators are able to manage them more effectively. 

##### Domain Controllers (DC):
A domain controller (DC) is a server computer that responds to security authentication requests. It's a network server in charge of granting hosts access to domain resources. It authenticates users, saves account information, and enforces a domain's security policy.

## Objects in Active Directory
Active Directory (AD) objects are entities that represent resources that exist in the AD network. Users, computers, printers, contact persons who may be vendors for the organisation, and other resources are examples of the AD objects.

**User:** In AD, each member of the organization is represented by a user object. The member's details, such as their first and last names, office, phone number, and so on, are stored in the user object.

**Contact:** AD contacts include information about a person’s or business’ such as phone numbers, email addresses etc.

**Printer:** Represents all the printers present in the organization’s network.

**Computer:** Contains information related to all the computers present within the organization.

**Shared Folder:** A pointer object that points to the location of a shared folder within the Active Directory network.

**Group:** Simply a collection of directory objects on which shared security policies can be assigned to them. User accounts, computer accounts, and other groups are grouped together into manageable units using groups. Working with groups rather than individual users makes network maintenance and administration easier.

## Conclusion
In this post we saw what Active Directory is and why is it so important and useful for organizations. We also looked at different components of the Active Directory, the basic structure and working of the AD. And finally different types of objects present in the AD network. All of this, however, is simply the tip of the iceberg. I strongly advise you to understand more about this topic. I've also included some references below where you can get more information.

<br>

And that is all for this post. Hope you enjoyed and learned something new. I'm thinking of writing some posts related to AD Exploitation in the future so stay tuned!

<br>

**Thanks for reading!**

<br>

# References 

- [https://www.quest.com/solutions/active-directory/what-is-active-directory.aspx](https://www.quest.com/solutions/active-directory/what-is-active-directory.aspx)

- [https://en.wikipedia.org/wiki/Active_Directory](https://en.wikipedia.org/wiki/Active_Directory)

- [https://www.lepide.com/blog/what-is-active-directory-and-how-does-it-work/](https://www.lepide.com/blog/what-is-active-directory-and-how-does-it-work/)

- [https://www.windows-active-directory.com/active-directory-ad-fundamentals.html](https://www.windows-active-directory.com/active-directory-ad-fundamentals.html)

- [https://www.serverbrain.org/active-directory-infrastructure-2003/logical-vs-physical-components.html](https://www.serverbrain.org/active-directory-infrastructure-2003/logical-vs-physical-components.html)

- [https://www.techtarget.com/searchwindowsserver/definition/Microsoft-Active-Directory-Domain-Services-AD-DS](https://www.techtarget.com/searchwindowsserver/definition/Microsoft-Active-Directory-Domain-Services-AD-DS)


