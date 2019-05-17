# Trazer
Allows the user to define templates to mactch Wireshark traces. 
Basically, a template is a test case (TC). It is matched against a Wireshark trace to check whether specific conditions are met. If they are met, then the TC is passed. Otherwise the TC fails and human analysis is required.

# Scope
Our target is to develop a tool that can be used to automatise acceptance testing of IMS, 4G and 5G system. However, we want to develop this tool in a generic way, so it can be used in any kind of testing where Wireshark traces need to be rutinely analysed to conclude whether a test case is passed or not.

# Introduction
Extracts information from Wireshark traces and parses it to check if it 
complies with specific rules.

Parsing is based on rule files which define:

1. Which packets to look at.
2. What should be validated on those packets pass a test case.

The tool supports dynamic parsing. This is, using values from one packet to 
look for related packets (e.g. responses).

The tool supports dynamic object return. This is, returning objects build by
the user from trace data or metadata.

# Trace extraction
To increase processing speed, you should always pre-filter the trace to reduce
it as much as possible. In the best case scenario, the trace should only 
contain the packets for the test case.

For example, if you have an IMS registration trace for a user with phone number
+43664xxxxxxx and IMSI 23201yyyyyyyyyy and you want to check SIP and Cx 
interface signalling, then you can apply a filter like
 
```
sip contains 664xxxxxxx or sip contains 23201yyyyyyyyyy or diameter.applicationId==16777216
```

where 16777216 is the identifier of the diameter applications of the Cx 
interface.

Use your best judgement to filter the trace appropriately.

**Note:** Do NOT use this tool with huge traces. Traces with tens of thousands
of packets will put your computer to its knees and may crash the application.

# Test Case specification

A test case (TC) is specified in a JSON file that contains a list of sequential rules.
Each rule specifies what needs to be matched in a frame to comply with this rule,
and what needs to be stored from a matched frame to be used in later matches.

A rule has two keys:

| Key | Content 
| ----- | --------
| match | set of rules to be matched against frames inside the trace.
| store | list of fields in a matching frame to be stored into variables.

Basically, a TC is a sequence of rules like:
```json
[
  {
    "match": {},
    "store": {}
  },
  
  ...
  
  {
    "match": {},
    "store": {}
  }
]
```
The "match" field must be present for all rules. The "store" field is optional. It 
is only needed when you want to store the value of a field inside "match" into a 
variable in order to inject it into the "match" field of a subsequent rule.

## *match* field
This field is a dictionary in which the keys are protocol names as defined inside 
Wireshark traces exported to JSON (e.g. "ip", "upd", "tcp", "https", "sip", etc.).
For each protocol inside **"match"**, you define a list of fields to match. 
For example:

```json
"match": {
    "udp": [
        {
            "port": "5060",
            "optional": false
        }
    ]
}
```

This rule will match any frame with udp content and port 5060. The **"optional"** 
field indicates if matching this field is optional or mandatory. If set to "false", 
then the frame will only pass the rule if it contains udp with port 5060. If set to 
"true", then the frame will pass even if there is not udp with port 5060.

***NOTE:** Optionality is defined to allow some fields to be "optionally" present. 
The match will not fail if the field is not present, but it will fail if the
field is present but has a different value.*

You can also specified values to be injected in run time. For example:

```json
"match": {
    "udp": [
        {
            "dstport": "{{sip_port}}",
            "optional": false
        }
    ]
}
```

The framework will try to find a value for *sip_port* in the configuration variables 
and in run time variables created during the execution of the test case using the 
"storage" field.

## *storage* field
As for "match", this field is also a dictionary in which the keys are protocol 
names as defined inside Wireshark traces exported to JSON. But unless "match",
the entries in this fields are not used for matching but for storing the value
found in a match for injection into "match" fields of subsequent frames.

For example:

```json
"store": {
    "sip": [
        {
            "msg_hdr_tree": {
                "Call-ID": "call_id"
            }
        }
    ]
}
```

# Test execution

```
python test.py <template_file> <test_file>
```