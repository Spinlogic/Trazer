# Trazer

Allows the user to define test cases (TC) to match against Wireshark traces. 
If the conditions defined for the TC are met, then the TC is passed. Otherwise
the TC fails and human analysis is required.

# Scope

Our target is to develop a tool that can be used to automatise acceptance 
testing of IMS, 4G and 5G system. However, we want to develop this tool in a
generic way, so it can be used in any kind of testing where Wireshark traces 
need to be rutinely analysed.

# Introduction

Parses Wireshark traces to check compliance with a set of rules defined in a
TC template.

The rule files define:

1. Which packets to look at.
2. What should be validated inside those packets to pass a test case.

The tool supports dynamic parsing. This is, using values from one packet to 
look for related packets (e.g. responses).

# Trace extraction

To increase processing speed, you should always pre-filter the trace to reduce
it as much as possible. In the best case scenario, the trace should only 
contain the packets for the test case.

For example, if you have an IMS registration trace for a user with phone number
+43664xxxxxxx and IMSI 23201yyyyyyyyyy and you want to check SIP and Cx 
interface signalling, then you should apply a filter like
 
```
sip contains 664xxxxxxx or sip contains 23201yyyyyyyyyy or diameter.applicationId==16777216
```

where 16777216 is the identifier of the diameter applications of the Cx 
interface.

Use your best judgement to filter the trace appropriately.

**Note:** Do NOT use this tool with huge traces. Traces with tens of thousands
of packets will put your computer to its knees and may crash your system.

# Test Case specification

A test case (TC) is specified in a JSON file that contains a list of sequential
rules. Each rule specifies what needs to be matched in a frame to comply with 
this rule, and what needs to be stored from a matched frame to be used in later
matches.

Rules are matched to frames sequentially. When a rule matches a frame, this 
rule is completed and the following rule will be matched against subsequent 
frames.

A TC can have the following keys:

| Key | Content 
| ----- | --------
| import | list of files to import. These files shall only contain variables and / or other imports.
| variables | key:value pairs of variables.
| template | list of rules to match.

Each *rule* inside a *template* can have the following keys:

| Key | Content 
| ----- | --------
| match | set of rules to be matched against frames inside the trace.
| store | list of fields in a matching frame to be stored into variables.

A *template* inside a TC is a sequence of rules like:
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
The "match" field **must** be present for all rules. The "store" field is 
**optional**. The "store" field is only needed when you want to store the value
of a field inside "match" into a variable in order to inject it into the"match" 
field of a subsequent rule.

## *match* field

This field is a dictionary in which the keys are protocol names as defined 
inside Wireshark traces exported to JSON (e.g. "ip", "upd", "tcp", "https", 
"sip", etc.). For each protocol inside **"match"**, you define a list of fields
to match. For example:

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

This rule will match any frame with udp content and port 5060. The 
**"optional"** field indicates if matching this field is optional or mandatory.
If set to "false", then the frame will only pass the rule if it contains udp 
with port 5060. If set to "true", then the frame will pass even if there is no 
udp with port 5060.

***NOTE:** While the match will not fail if the field is not present, it will 
however fail if the field is present but has a different value.*

You can also specify values to be injected at run time. For example:

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

The framework will try to find a value for *sip_port* in the configuration 
and in run time variables created during the execution of the test case using
the "storage" field.

## *storage* field

This field is a dictionary in which the keys are protocol names as defined 
inside Wireshark traces exported to JSON. The values in these fields are 
stored in variables so they can be injected in *match* fields of later rules
for subsequent frames.

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

# Export pcap to JSON

When exporting Wireshark traces to JSON make sure that:

1. There are no duplicate keys.
2. The proper filter to the trace is applied.
3. The output format is valid JSON.
 
"tshark_filtering.cmd" provides a windows script that can be used to export
files with the correct format. Its usage is:

```
tshark_filtering.cmd input_pcap_file output_pcap_file filter
```

For example:

```
tshark_filtering.cmd .\traces\trace001.pcap .\filtered\trace001.json "sip contains 12345678"
``` 

# Test execution

The command to execute a TC against a trace file is:

```
python test.py <template_file> <trace_file>
```

For example:

```
python test.py .\test_cases\tc001.json .\filtered\trace001.json
```

