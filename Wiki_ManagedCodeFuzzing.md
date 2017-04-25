| Metadata Title       |   |
|----------------------|---|
| Metadata Description |   |

Managed Code Fuzzing

The following chart depicts the possible security impact (“I:”) and worst-case
security severity (“S:”) of bugs identifiable by the fuzzers included in Project
Springfield based on target type, data trust, and code type (native versus
managed). A discussion of these topics can be found below.

<table >
<tr><td style="background-color:red;">1</td><td>2</td><td>3</td></tr>
<tr><td>4</td><td>5</td><td>6</td></tr>
</table>


| Target Type                                                                      | Data Trust                                                                                             | Native                   | Managed             |
|----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|--------------------------|---------------------|
| Service – 0 Click (Network listener like web service, COM server, sockets, etc.) | Trusted Parsed data’s source and author are strongly authenticated; data integrity is verified         | I: EOP, DOS S: Moderate  | I: DOS S: Low       |
|                                                                                  | Partially-Trusted Parsed data’s source and author are weakly authenticated; data integrity is unknown  | I: EOP, DOS S: Important | I: DOS S: Moderate  |
|                                                                                  | Untrusted Source, author, and integrity of parsed data are unknown                                     | I: EOP, DOS S: Critical  | I: DOS S: Important |
| Desktop App – 1+ Click (browser, media player, graphics, accounting, etc.)       | Trusted Parsed data’s source and author are strongly authenticated; data integrity is verified         | I: EOP, DOS S: Moderate  | I: DOS S: Low       |
|                                                                                  | Partially -Trusted Parsed data’s source and author are weakly authenticated; data integrity is unknown | I: EOP, DOS S: Important | I: DOS S: Moderate  |
|                                                                                  | Untrusted Source, author, and integrity of parsed data are unknown                                     | I: EOP, DOS S: Critical  | I: DOS S: Moderate  |

# xCode, Data Trust, and Application Types


These three attributes of a given computer program are generally sufficient to
determining its code security risk, and therefore the utility of fuzz testing
(defined below).

## Code Type: Managed v. Native

**Managed code** is defined as source code whose execution requires and occurs
in the context of a virtualized environment – such as the .NET Common Language
Runtime (CLR) or the Java Virtual Machine (JVM) – that provides memory
management, type safety, exception handling, threading, and other runtime
services, in lieu of requiring developers to implement them. The benefits of
managed code include security and reliability guarantees, but come at the cost
of a larger resource footprint and performance penalty, depending on the VM.

Unmanaged code, or **native code**, by comparison, is source code that compiles
directly to an x86/x64 executable image; developers must handle many tasks such
as memory allocation and deallocation, object lifetime, and so on. While it is
more performant than managed code, native code lacks many of the automatic
security safeguards, especially those around memory safety: it’s faster, but
harder to implement safely.

Applications may contain both native and managed code in the following three
cases:

-   C++ with the Common Language Infrastructure
    ([C++/CLI](https://en.wikipedia.org/wiki/C%2B%2B/CLI))

-   [Interoperability](https://msdn.microsoft.com/en-us/library/ms173184.aspx)
    via Platform Invoke and COM Interop

-   Use of the [unsafe](https://msdn.microsoft.com/en-us/library/chfa2zb8.aspx)
    keyword

## Applications: Service v. Desktop 

To oversimplify, a **desktop application** (console or GUI) is launched as
needed by a user; a **service** (or server application) is designed to start and
run without user interaction. The key distinction is the degree of user activity
(e.g., ‘number of clicks’) necessary to expose a given data parser to
potentially attacker-supplied data.

A **parser** is a software component that consumes input data and makes
execution decisions based on that data. For example, the parser might allocate
and populate memory structures, call API functions based on the data in the
structures, or manipulate contained data. A parser can be implemented in native
or managed code, or a hybrid of the two. Parsing is a very common operation
found in almost all applications ranging from compilers to media players to
network stacks; importantly, parsing is more than just *transmitting* the input
data to another location; rather it involves *acting* on that data.

Services typically listen on the network for incoming data, and respond based on
that data: e.g., a web service might receive a SOAP or HTTP request, parse it,
and send a response back to the caller. A desktop app might be used to author or
load in content that is parsed and displayed in a GUI.

Data: Trusted v. Untrusted 
---------------------------

A fundamental part of [threat
modeling](https://www.owasp.org/index.php/Application_Threat_Modeling), or
identifying and mitigating threats to an application (desktop or service), is
determining exactly how well-trusted the data is that the application parses.

At one end of the spectrum is (fully) **Trusted Data:** data with a
cryptographically-verified author or source, that has been transmitted privately
and securely to the receiving system in the manner the system expects, to the
end of causing the system to behave as designed.

At the other is (fully) **Untrusted Data**: data with unknown or unproveable
author or source, that cannot be guaranteed to be security, untampered, private,
or safe in the sense of causing the system to behave as designed.

Some simple examples: any data obtained from an anonymous source should be
considered fully untrusted, like a media file or executable downloaded from an
unfamiliar site on the internet. Data obtained from a web site protected by TLS
(“https”), or a doc sent by a known friend (after the appropriate phishing
check) could be considered semi-trusted, as could data vouched for by a
reputation service (that you trust). There’s a *chance* it’s attacker
controlled, but not as likely as what you might download via an unknown URI in
unsolicited email touting performance enhancing drugs. Fully trusted data is
created by a known agent and protected from tampering: the configuration files
created by a service application ACL’d to SYSTEM only, a signed and sealed
message payload from a known sender, source code pulled from your company’s
repository.

Fuzzing
=======

**Fuzzing** is the action of mutating a parser’s input data, typically with the
intention of triggering a crash, exception, or other fault condition.
Generically, a f**uzzer** is a tool that performs automated negative testing of
a parser by repeatedly supplying it with fuzzed input data.

This input data might be binary media read in from a file, structured XML from a
network stream as part of a protocol, text from a UI element on a web page, and
so on. The structure of the target data ranges from:

-   Binary data

-   Unstructured text

-   Structured text/hybrid (XML, JSON, PDF)

-   Stateful protocols

Project Springfield currently includes a suite of file fuzzers, meaning that the
input data that gets fuzzed and supplied to the target application’s parser(s)
is read in from a set of files. They are more effective (in general) against
binary data and unstructured text, as structured data or stateful protocols
typically require grammars to maximize effectiveness.

Regardless of the format and source of a parser’s input data, a fuzzer is
designed to supply values to the parser that cause it to malfunction. If and
when that occurs, it is then important to understand the type of bug, the
exploitability of that bug, and most importantly, the potential impact of the
bug on the containing application or service – whether it’s an actual security
vulnerability, and if it is, how bad it is, and how critical it is to fix it.

Security Impact
===============

**A security bug** is a bug that can be triggered by an attacker that has a
security impact on the application or service. Such a bug is also known as a
**vulnerability**. **Security Impact** (also called security effect) is the
potential security-related consequence of the vulnerability. Put another way, it
describes what an attacker achieves by exploiting the vulnerability.

In general, fuzzing bugs have one of the following security impacts:

-   **Denial of service** (DOS): the attacker disrupts the normal operation of
    the software, either temporarily (for a minute, hour, or longer) or
    permanently (until restart, reboot, or reinstallation)

-   **Elevation of privilege** (EOP): the attacker assumes some level of control
    not granted to the standard user, or successfully executes arbitrary code

Note that in this context, DOS refers to the impact on the application or
service of a single execution of a parser; for example, a ‘packet of death’ that
crashes a network listener’s process. A *distributed* denial of service (DDOS)
attack works by flooding a parser with (valid) input data in an effort to
exhaust its resources; a fuzzer does not mitigate this.

Elevation of Privilege
----------------------

As a general rule, managed code is not susceptible to EOPs. The reason is that
the techniques for exploiting memory corruption bugs in a parser, for example,
require the ability to manipulate pointers and register values in a way that
affects program execution. Managed code by design does not allow this sort of
manipulation.

Native code, on the other hand, does allow this sort of manipulation. Used
correctly, pointers and other native code constructs allow for extremely fast
execution. Used incorrectly, the following sorts of bugs may result, any of
which could lead to a read or write access violation, and potentially an EOP:

-   Buffer overflow (stack/heap/global)

-   Format string errors

-   Integer overflow (underflow/signedness)

-   Over-indexing bug (and/or underindexing)

-   Use after free, double free

-   NULL + offset write (exploitable NULL dereference)

Denial of Service
-----------------

Both native and managed code data parsers are susceptible to denial of service
attacks that result from logic and other errors caused by not properly
sanitizing input data. This can result in unhandled exceptions, deadlocks, or
memory spikes that temporarily or permanently DOS a desktop or service process.
These are often considered reliability bugs; the distinction is when they can be
caused by an attacker (a.k.a. with a fuzzer).

In addition to logic errors, native code can also be caused to crash via memory
errors such as null pointer dereferencing and out-of-bounds reads, if they can
be triggered by an attacker.

Aside: Reliability
------------------

[Reliability](https://en.wikipedia.org/wiki/Software_reliability_testing) is
loosely defined as the probability an application runs without failure for a
given time span in a given environment or, equivalently, as the average time you
can expect the application to run until it fails (a.k.a. MTBF). Reliability
failures are typically caused by resource exhaustion due to leaks, race
conditions leading to hangs or deadlocks, invalid state, handled exceptions with
flaws in the handler, etc. – conditions that fuzz testing is designed to trigger
or uncover. Thus, a DOS vulnerability in an application is really just a
reliability bug, albeit one that can be triggered by an attacker; a fuzzer
therefore provides excellent reliability testing as well, for both managed and
native code.

Aside: Design versus Code Bugs
------------------------------

It is important to note that code bugs aren’t the only bugs that allow an
attacker to achieve EOP or DOS: design bugs can (and often do) as well. Unlike
code bugs that can be found by a fuzzer, however, design bugs are architectural
artifacts typically stemming from poorly-designed logic or insufficient threat
mitigation. (As a rule, you cannot secure your code unless you know its threats;
threat modeling is the process of enumerating them.) Consider two simple
examples.

First, insecure crypto: an application’s designer mistakenly opts for a
deprecated hash algorithm (e.g., MD5), chooses a very low symmetric key size
(e.g., 32 bits), or calls the rand() function for a random number instead of
leveraging a cryptographically strong random number generator (RNG). In each
case, the system will run as designed, but be vulnerable to attack.

Second, logic flaw: consider a routine that (stupidly) grants privileged access
to a given caller if authorization checks for lesser access grants fail (i.e.,
insecure default). The fuzzer would find the conditions that would cause those
authorization checks to fail, resulting in higher privilege than intended, but
with no apparent error (since that is how the code is supposed to function).

Security Severity
=================

While a given vulnerability’s security effect describes what can happen if it’s
exploited, the *risk* the vulnerability poses to the containing application
depends on the lowest level of trust the application can be expected to consume,
plus the amount of user activity necessary to expose the vulnerability to an
attacker.

One way of describing this risk – which can also be thought of as the urgency of
*fixing* the vulnerability once it’s found – is via a measure called **Security
Severity**: *Low*, *Moderate*, *Important*, or *Critical*. This algorithmic
approach to determining the risk of a security bug based on various attributes
was first developed by the Microsoft Security Response Center (MSRC) in the
early 2000s, and is outlined
[here](https://technet.microsoft.com/en-us/security/gg309177.aspx).

These rankings have been used internally at Microsoft to streamline the triage
process: a critical bug is a ‘ship blocker’ that is must-fix prior to release;
low and moderate bugs might be postponed as technical debt, depending on a
team’s available bandwidth and point in the release cycle.

The chart above indicates the worst-case security severity of a hypothetical bug
given the following:

-   That application’s code type, native or managed

    -   Hybrid code should be considered native, depending on the complexity and
        exposure of the native implementation

    -   Applications written in scripting languages like JavaScript or Ruby can
        be treated as managed for these purposes, so long as they do not expose
        direct memory access and are strongly typed

-   Trust of the data parsed by the application

-   User action necessary to expose the application to an attacker

Summary
=======

We offer the following recommendations regarding fuzzing:

| Native code data parsers should be fuzzed: |
|--------------------------------------------|


-   Especially if they have not been previously fuzzed

    -   Especially if they were implemented without the rigorous use of static
    analysis

    -   Especially if they are in a sensitive or high-business-impact application or
    service

-   Whenever the parser logic undergoes significant churn

-   Managed code data parsers should be fuzzed:

-   If they are in a sensitive or high-business-impact service

-   Especially if they parse untrusted data

-   Whenever the parser logic undergoes significant churn
