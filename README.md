# Dixie Vuln Scanner Plugin (v0.1)
Author: **3Flatline LLC**

_Powerful static code analyzer that uses a db of 200k vulnerabilities to scan and find bugs in a number of languages._

## Description:

The Dixie Code Scanner plugin leverages the Dixie Code Scanner engine https://3flatline.ai to find vulnerabilities in a number of languages better than other SAST tools. This Binja integration leverages specific features of the engine for C analysis and allows a user to submit decompiled functions directly from the Binary Ninja window.  Users have the capability to get function descriptions and optionally scan for vulnerabilities in the decompiled code.

This plugin requires a scubscription to the Dixie Code Scanner, which can be purchased at (https://3flatline.ai/binja)

Check out our overview video here: https://www.youtube.com/watch?v=7IEUEgoZC9Q

But 3Flatline, why would I use an LLM for Reverse Engineering? I don't want anyone to know what I'm doing!

Touche, but the Dixie Code Scanner engine is designed to be as private as possible while still leveraging medium/large versions of LLMs, which we have found to be the most performant at specific tasks. Contrary to "throwing code at an LLM", it turns out most LLMS are TERRIBLE at code analysis. So the Dixie Code Scanner engine does a significant amount of analysis before even getting to an LLM.

"Well, how is it private?"
-You, probably

Our thoughts:
- We don't retain or retrain on any of your data. All the data we use in our process to identify vulnerabilities is pure: no false positives. Adding your code with "potential" vulnerabilities dilutes the effectiveness of our process.
- We run a combination of self-hosted models and private inference endpoints using models we have found to be the most performant for certain tasks. None of these models are retraining on your data and the privacy policies of our providers mimic this.
- No self-identifying information is sent from our engine to the LLMs (unless you put your name in your code).
- Our database automatically deletes results after 7 days because we don't want to be a massive db of code weaknesses.
- Your code snippets are deleted immediately upon analysis from our servers.
- We have designed in local storage to this plugin: so don't keep things on the server or we will delete them!
- Logs in the backend don't store your source data, it specifically captures what is happening in the engine for debugging to stop accidental retention.

3Flatline was founded by a pair of hackers who understand where you are coming from and have built a platform sensitive to that. It turns out the privacy researchers care about is the same kind of privacy enterprises care about. We would rather make a business supporting vulnerability research than harvesting your data.

*If you're a business or government agency and REALLY want something more private, reach out to info@3flatline.ai. We have other deployment models like deploying into your tentant or running a full offline box for ultra-sensitive environments.* 


## Installation Instructions

### Darwin

no special instructions, package manager is recommended

### Linux

no special instructions, package manager is recommended

### Windows

no special instructions, package manager is recommended

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

* 1528



## Required Dependencies

The following dependencies are required for this plugin:

 * pip - pygments>=2.7.0,<2.9.0


## License

This plugin is released under a MIT license.

## Metadata Version

2
