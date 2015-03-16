# Secure Self hosted Synchronization and Sharing Service  (S5)


For private users, the comfort of  accessing information like calendars,
contacts, notes, bookmarks and files from different devices or sharing it with
others comes hand in hand with loss of control over that information by
submitting it to service providers with dubious privacy policies. This is avoided by using
the **S5**.


**S5** synchronizes pieces of information (items) between devices using
a server. All data is encrypted on the client in a way that it can only be
decrypted by authorized users. Fine grained access control on the server
ensures, that data can not be corrupted by unauthorized users and helps to
protect the data in case the encryption can be circumvented.
Users can choose which servers their data may be submitted to or set up their
own server, allowing them to stay in full control of their private data.

**Various kinds of information** are supported, including: calendar events, contacts,
bookmarks, photos, documents, news and files in general.

**All cryptographic functionality is provided by plugins** making it easy to
replace a library, in which weaknesses are discovered, with a more secure one.

**Cryptographic algorithms can be chosen individually**
for every resource or connection that is to be encrypted,
allowing to switch to a more secure algorithm in the future.

**The protocol uses open standards** and is itself publicly available
so it can be extended and alternative implementations can be created to support
as many devices as possible, regardless of the operating system, the
manufacturer or the vendor.

**Multiple Servers** can be used to synchronize the same information, which
increases the availability in case of a server failure, and to work with
different groups of people that use different servers.

Server and Client are written in Python, so they can
be used on Linux, Mac OS X, Windows and other platforms at some point in the
future, currently only linux is supported.
