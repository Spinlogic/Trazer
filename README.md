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
rules. Each rule specifies what needs to be matched in a [Wireshark] frame to 
comply with this rule, and what needs to be stored from a matched frame to be 
used in later matches.

Rules are matched to frames sequentially. When a rule matches a frame, this 
rule is completed and the following rule will be matched against subsequent 
frames.

A TC can have the following root level keys:

| Key | Content 
| ----- | --------
| import | list of files to import. These files shall only contain variables and / or other imports.
| variables | key:value pairs of variables.
| metadata | tag / value pairs that will be directly copied to the report of the TC.
| template | list of rules to match.

Each *rule* inside a *template* can have the following keys:

| Key | Content 
| ----- | --------
| optional | If true, the TC continues to be evaluated even if this rule is not matched. Default = false.
| metadata | tag / value pairs that are directly copied to the report of the rule inside the report of the TC.
| match | set of rules to be matched against frames inside the trace.
| store | list of fields in a matching frame to be stored into variables.
| report | list of tag / value pairs to report when the rule is matched.
| verify | list of variable / value pairs which must be verified when the rule is matched. The rule is "Passed" passed only if these conditions are met.

A *template* inside a TC is a sequence of rules like:
```json
[
  {
    "optional": false,
    "metadata": {},
    "report": {},
    "match": {},
    "verify": {},
    "store": {}
  },
  
  ...
  
  {
    "optional": false,
    "metadata": {},
    "report": {},
    "match": {},
    "verify": {},
    "store": {}
  }
]
```
The "match" field **must** be present for all rules. All the other fields are  
**optional**.

The "store" field is used to store the value of a field inside "match" into a variable in order to inject it into the"match" 
field of a subsequent rule.

## *optional* field

Indicates whether the rule is optional or mandatory. If the field is not 
present, then the default value (false) applies.

If *optional* is set to **false**, then the TC will fail if this rule is not 
matched against a frame in the trace.

If *optional* is set to **true**, then this rule will be skipped if it is not
matched by any frame in the trace, and subsequent rules will be evaluated.

## *metadata* fields

The contents of these fields, whether they appear at TC level or rule level, 
are copied as such to the TC report. It is a purely informative field.

 ```json
 "metadata": {
    "name": "TC08#007",
    "description": "VoLTE UE in CS Network Places a Call to VoWiFi UE"
  }
 ```
You can add whatever key / value pairs you want to metadata fields, and they
will show up in the report.

## *match* field

This field is a dictionary in which the keys are protocol names as defined 
inside Wireshark traces exported to JSON (e.g. "ip", "upd", "tcp", "https", 
"sip", etc.). For each protocol inside **"match"**, you define a list of 
conditions to match to match. The key for a condition must be the same
as the key inside the frame. For example:

```json
"match": {
    "udp": [
        {
            "udp.port": "5060",
            "optional": false
        }
    ]
}
```

This rule will match any frame with udp content and udp.port 5060. 

The **"optional"** field indicates if matching this field is optional or 
mandatory. If set to "false", then the frame will only pass the rule if it 
contains udp with port 5060. If set to "true", then the frame will still pass 
this condition if the key "udp.port" is not found inside it.

***NOTE:** For an "optional" condition, while the match will not fail if the 
field is not present, it will however fail if the field is present but has a 
different value.*

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

# *report* field

List of tag / value pairs to be added to the report of the TC.

For example:
```json
"report": [
        {
          "tag": "From",
          "value": "{{msisdn_a}}"
        },
        {
          "tag": "To",
          "value": "{{msisdn_b}}"
        },
        {
          "tag": "UNI Call-ID",
          "value": "{{call_id}}"
        },
        {
          "tag": "Offered codecs",
          "value": "{{uni_offered_codecs}}"
        }
      ]
 ```
 
 # *verify* field
 
 List of variable / value pairs to verify to pass the TC.
 
 The presence of this field is optional. It shall only be present when there is
 a need to verify specific conditions inside a matched frame.
 
 Once a rule has been matched to a frame, the conditions inside the *verify*
 field are checked for the frame. If these conditions are not met, the the TC
 "Fails".

***NOTE**: the "optional" field only dictates what to do in case a rule is not
matched to any frame. Once a rule is matched, the conditions inside "verify" 
must be met regardless of the value of "optional".*

***NOTE**: for non-optional frames, putting conditions inside a "verify" field
has the same effect in terms of overall TC result as putting them inside the
"match" field. The main difference is that a condition in "verify" is only 
evaluated when the frame is matched and the outcome is reflected in the report
for the rule. An unmet condition in "match" will result in the rule not being
matched to any frame, and no report is generated for this rule.* 

# TC Report

The Test Case report is built from the metadata of the TC and its rules, and 
from the *report* fields inside the TC's rules.

The TC report has JSON format and looks like:

```json
{
   "result": "Passed",
   "rules": [
      {
         "metadata": {
            "name": "UNI INVITE",
            "description": "This INVITE does not show in all traces since IPSec is used in UNI"
         },
         "result": "Passed",
         "From": "\\+816946787322",
         "To": "\\+816946787321",
         "UNI Call-ID": "22r8rmalaah09a82rpjv9rmp98j2mv0m@10.18.5.64",
         "Offered codecs": "['rtpmap:101 AMR-WB/16000', 'fmtp:101 mode-set=0,1,2', 'rtpmap:108 AMR/8000', 'fmtp:108 mode-set=7', 'rtpmap:102 AMR/8000', 'fmtp:102 mode-set=0,2,4,7', 'rtpmap:96 AMR/8000', 'fmtp:96 mode-set=7', 'rtpmap:8 PCMA/8000', 'rtpmap:100 AMR/8000', 'fmtp:100 mode-set=0,2,4,7;mode-change-neighbor=1;mode-change-period=2', 'rtpmap:116 telephone-event/16000', 'rtpmap:97 telephone-event/8000', 'ptime:20']",
         "optional": false
      },
      {
         "metadata": {
            "name": "183 response",
            "description": "Screen selected codec"
         },
         "result": "Failed",
         "optional": true
      },
      {
         "metadata": {
            "name": "200 response",
            "description": "Session established"
         },
         "result": "Passed",
         "Selected_Codec": "['rtpmap:101 AMR-WB/16000/1', 'fmtp:101 mode-set=0,1,2;mode-change-capability=2;max-red=0', 'ptime:20', 'maxptime:240', 'sendrecv', 'rtpmap:116 telephone-event/16000']",
         "optional": false
      }
   ],
   "metadata": {
      "name": "TC08#007",
      "description": "VoLTE UE in CS Network Places a Call to VoWiFi UE"
   }
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
tshark_filtering.cmd input_pcap_file output_json_file filter
```

For example:

```
tshark_filtering.cmd .\traces\trace001.pcap .\filtered\trace001.json "sip contains 12345678"
``` 

# Test execution

The command to execute a TC against a trace file is:

```
python test.py <template_file> <trace_file> <report_file>
```

For example:

```
python test.py .\test_cases\tc001.json .\filtered\trace001.json .\reports\tc001.txt
```

